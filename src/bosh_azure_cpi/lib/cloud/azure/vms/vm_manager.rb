# frozen_string_literal: true

module Bosh::AzureCloud
  class VMManager < VMManagerBase
    def initialize(azure_config, registry_endpoint, disk_manager, disk_manager2, azure_client, storage_account_manager, stemcell_manager, stemcell_manager2, light_stemcell_manager)
      super(azure_config.use_managed_disks, azure_client, stemcell_manager, stemcell_manager2, light_stemcell_manager)

      @azure_config = azure_config
      @registry_endpoint = registry_endpoint
      @disk_manager = disk_manager
      @disk_manager2 = disk_manager2
      @azure_client = azure_client
      @storage_account_manager = storage_account_manager
      @stemcell_manager = stemcell_manager
      @stemcell_manager2 = stemcell_manager2
      @light_stemcell_manager = light_stemcell_manager
      @use_managed_disks = azure_config.use_managed_disks
    end

    def create(bosh_vm_meta, location, vm_props, network_configurator, env)
      # network_configurator contains service principal in azure_config so we must not log it.
      CPILogger.instance.logger.info("create(#{bosh_vm_meta}, #{location}, #{vm_props}, ..., ...)")

      instance_id = _build_instance_id(bosh_vm_meta, location, vm_props)

      resource_group_name = vm_props.resource_group_name
      vm_name = instance_id.vm_name

      # When both availability_zone and availability_set are specified, raise an error
      cloud_error("Only one of 'availability_zone' and 'availability_set' is allowed to be configured for the VM but you have configured both.") if !vm_props.availability_zone.nil? && !vm_props.availability_set.name.nil?
      zone = vm_props.availability_zone
      unless zone.nil?
        cloud_error("'#{zone}' is not a valid zone. Available zones are: #{AVAILABILITY_ZONES}") unless AVAILABILITY_ZONES.include?(zone.to_s)
      end

      _ensure_resource_group_exists(resource_group_name, location)

      # tasks to prepare resources for VM
      #   * prepare stemcell
      #   * prepare network interfaces, including public IP, NICs, LB, AG, etc
      #   * prepare availability set
      #   * prepare storage account for diagnostics
      tasks = []

      tasks.push(
        task_get_stemcell_info = Concurrent::Future.execute do
          _get_stemcell_info(bosh_vm_meta.stemcell_cid, vm_props, location, instance_id.storage_account_name)
        end
      )

      # When availability_zone is specified, VM won't be in any availability set;
      # Otherwise, VM can be in an availability set specified by availability_set or env['bosh']['group']
      availability_set_name = vm_props.availability_zone.nil? ? _get_availability_set_name(vm_props, env) : nil

      primary_nic_tags = AZURE_TAGS.dup
      # Store the availability set name in the tags of the NIC
      primary_nic_tags['availability_set'] = availability_set_name unless availability_set_name.nil?
      tasks.push(
        task_create_network_interfaces = Concurrent::Future.execute do
          _create_network_interfaces(resource_group_name, vm_name, location, vm_props, network_configurator, primary_nic_tags)
        end
      )

      tasks.push(
        task_get_or_create_availability_set = Concurrent::Future.execute do
          availability_set = _get_or_create_availability_set(resource_group_name, availability_set_name, vm_props, location)
        end
      )

      tasks.push(
        task_get_diagnostics_storage_account = Concurrent::Future.execute do
          diagnostics_storage_account = _get_diagnostics_storage_account(location)
        end
      )

      # Calling .wait before .value! to make sure that all tasks are completed.
      # The purpose of calling .wait before .value! is to make sure that all processes are completed
      #    before raising an error. It is important when creating a VM, because on Azure you can't
      #    delete a resource that is on-provisioning.
      tasks.map(&:wait)

      stemcell_info = task_get_stemcell_info.value!
      network_interfaces = task_create_network_interfaces.value!
      availability_set = task_get_or_create_availability_set.value!
      diagnostics_storage_account = task_get_diagnostics_storage_account.value!

      # create vm params
      vm_params = {
        name: vm_name,
        location: location,
        tags: _get_tags(vm_props),
        vm_size: vm_props.instance_type,
        managed: @use_managed_disks
      }

      vm_params[:zone] = zone.to_s unless zone.nil?
      vm_params[:os_disk], vm_params[:ephemeral_disk] = _build_disks(instance_id, stemcell_info, vm_props)
      vm_params[:os_type] = stemcell_info.os_type

      if stemcell_info.is_light_stemcell?
        vm_params[:image_reference] = stemcell_info.image_reference
      elsif @use_managed_disks
        vm_params[:image_id] = stemcell_info.uri
      else
        vm_params[:image_uri] = stemcell_info.uri
      end
      case stemcell_info.os_type
      when 'linux'
        vm_params[:ssh_username]  = @azure_config.ssh_user
        vm_params[:ssh_cert_data] = @azure_config.ssh_public_key

        user_data = Bosh::AzureCloud::BoshAgentUtil.get_encoded_user_data(@registry_endpoint, instance_id.to_s, network_configurator.default_dns)
        vm_params[:custom_data] = user_data
      when 'windows'
        # Generate secure random strings as username and password for Windows VMs
        # Users do not use this credential to logon to Windows VMs
        # If users want to logon to Windows VMs, they need to add a new user via the job 'user_add'
        # https://github.com/cloudfoundry/bosh-deployment/blob/master/jumpbox-user.yml
        #
        # https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/virtualmachines-create-or-update
        # adminUsername:
        #   Max-length (Windows): 20 characters
        vm_params[:windows_username] = SecureRandom.uuid.delete('-')[0, 20]
        # adminPassword:
        #   Minimum-length (Windows): 8 characters
        #   Max-length (Windows): 123 characters
        #   Complexity requirements: 3 out of 4 conditions below need to be fulfilled
        #     Has lower characters
        #     Has upper characters
        #     Has a digit
        #     Has a special character (Regex match [\W_])
        vm_params[:windows_password] = "#{SecureRandom.uuid}#{SecureRandom.uuid.upcase}".split('').shuffle.join
        computer_name = generate_windows_computer_name
        vm_params[:computer_name] = computer_name
        vm_params[:custom_data]   = Bosh::AzureCloud::BoshAgentUtil.get_encoded_user_data(@registry_endpoint, instance_id.to_s, network_configurator.default_dns, computer_name)
      end

      vm_params[:diag_storage_uri] = diagnostics_storage_account[:storage_blob_host] unless diagnostics_storage_account.nil?

      _create_virtual_machine(instance_id, vm_params, network_interfaces, availability_set)

      [instance_id, vm_params]
    rescue StandardError => e
      error_message = ''
      if @keep_failed_vms
        # Including undeleted resources in error message to ask users to delete them manually later
        error_message = 'This VM fails in provisioning after multiple retries.\n'
        error_message += 'You need to delete below resource manually after finishing investigation.\n'
        error_message += "\t Resource Group: #{resource_group_name}\n"
        error_message += "\t Virtual Machine: #{vm_name}\n"
        if @use_managed_disks
          os_disk_name = @disk_manager2.generate_os_disk_name(vm_name)
          error_message += "\t Managed OS Disk: #{os_disk_name}\n"

          unless vm_params[:ephemeral_disk].nil?
            ephemeral_disk_name = @disk_manager2.generate_ephemeral_disk_name(vm_name)
            error_message += "\t Managed Ephemeral Disk: #{ephemeral_disk_name}\n"
          end
        else
          storage_account_name = instance_id.storage_account_name
          os_disk_name = @disk_manager.generate_os_disk_name(vm_name)
          error_message += "\t OS disk blob: #{os_disk_name}.vhd in the container #{DISK_CONTAINER} in the storage account #{storage_account_name} in default resource group\n"

          unless vm_params[:ephemeral_disk].nil?
            ephemeral_disk_name = @disk_manager.generate_ephemeral_disk_name(vm_name)
            error_message += "\t Ephemeral disk blob: #{ephemeral_disk_name}.vhd in the container #{DISK_CONTAINER} in the storage account #{storage_account_name} in default resource group\n"
          end

          error_message += "\t VM status blobs: All blobs which matches the pattern /^#{vm_name}.*status$/ in the container #{DISK_CONTAINER} in the storage account #{storage_account_name} in default resource group\n"
        end
      else
        begin
          tasks = []
          # Delete the empty availability set
          tasks.push(
            Concurrent::Future.execute do
              _delete_empty_availability_set(resource_group_name, availability_set[:name]) if availability_set
            end
          )

          tasks.push(
            Concurrent::Future.execute do
              # Delete NICs
              if network_interfaces
                network_interfaces.each do |network_interface|
                  @azure_client.delete_network_interface(resource_group_name, network_interface[:name])
                end
              else
                # If create_network_interfaces fails for some reason, some of the NICs are created and some are not.
                # CPI need to cleanup these NICs.
                _delete_possible_network_interfaces(resource_group_name, vm_name)
              end

              # Delete the dynamic public IP
              dynamic_public_ip = @azure_client.get_public_ip_by_name(resource_group_name, vm_name)
              @azure_client.delete_public_ip(resource_group_name, vm_name) unless dynamic_public_ip.nil?
            end
          )

          # TODO: delete the config disk.

          tasks.map(&:wait)
          tasks.map(&:wait!)
        rescue StandardError => error
          error_message = 'The VM fails in creating but an error is thrown in cleanuping network interfaces or dynamic public IP.\n'
          error_message += "#{error.inspect}\n#{error.backtrace.join("\n")}"
        end
      end

      error_message += e.inspect

      # Replace vmSize with instance_type because only instance_type exists in the manifest
      error_message = error_message.gsub!('vmSize', 'instance_type') if error_message.include?('vmSize')
      raise Bosh::Clouds::VMCreationFailed.new(false), "#{error_message}\n#{e.backtrace.join("\n")}"
    end

    def find(instance_id)
      @azure_client.get_virtual_machine_by_name(instance_id.resource_group_name, instance_id.vm_name)
    end

    def delete(instance_id)
      CPILogger.instance.logger.info("delete(#{instance_id})")

      resource_group_name = instance_id.resource_group_name
      vm_name = instance_id.vm_name
      vm = @azure_client.get_virtual_machine_by_name(resource_group_name, vm_name)

      # Delete the VM
      if vm
        if vm[:availability_set].nil?
          @azure_client.delete_virtual_machine(resource_group_name, vm_name)
        else
          availability_set_name = vm[:availability_set][:name]
          flock("#{CPI_LOCK_PREFIX_AVAILABILITY_SET}-#{availability_set_name}", File::LOCK_SH) do
            @azure_client.delete_virtual_machine(resource_group_name, vm_name)
          end
        end
      end

      # After VM is deleted, tasks that can be run in parallel are:
      #   * deleting empty availability set
      #   * deleting network interfaces, then deleting dynamic public IP which is bound to them.
      #   * deleting disks (os disk, ephemeral disk)
      tasks = []

      # Delete availability set
      availability_set_name = nil
      if vm
        availability_set_name = vm[:availability_set][:name] unless vm[:availability_set].nil?
      else
        # If the VM is deleted but the availability sets are not deleted due to some reason, BOSH will retry and VM will be nil.
        # CPI needs to get the availability set name from the primary NIC's tags, and delete it.
        network_interfaces = @azure_client.list_network_interfaces_by_keyword(resource_group_name, vm_name)
        network_interfaces.each do |network_interface|
          availability_set_name = network_interface[:tags]['availability_set'] unless network_interface[:tags]['availability_set'].nil?
        end
      end
      unless availability_set_name.nil?
        tasks.push(
          Concurrent::Future.execute do
            _delete_empty_availability_set(resource_group_name, availability_set_name)
          end
        )
      end

      # Delete network interfaces and dynamic public IP
      tasks.push(
        Concurrent::Future.execute do
          _delete_possible_network_interfaces(resource_group_name, vm_name)
          # Delete the dynamic public IP
          dynamic_public_ip = @azure_client.get_public_ip_by_name(resource_group_name, vm_name)
          @azure_client.delete_public_ip(resource_group_name, vm_name) unless dynamic_public_ip.nil?
        end
      )

      # Delete OS & ephemeral disks
      if instance_id.use_managed_disks?
        tasks.push(
          Concurrent::Future.execute do
            os_disk_name = @disk_manager2.generate_os_disk_name(vm_name)
            @disk_manager2.delete_disk(resource_group_name, os_disk_name)
          end
        )

        tasks.push(
          Concurrent::Future.execute do
            ephemeral_disk_name = @disk_manager2.generate_ephemeral_disk_name(vm_name)
            @disk_manager2.delete_disk(resource_group_name, ephemeral_disk_name)
          end
        )
      else
        storage_account_name = instance_id.storage_account_name

        tasks.push(
          Concurrent::Future.execute do
            os_disk_name = @disk_manager.generate_os_disk_name(vm_name)
            @disk_manager.delete_disk(storage_account_name, os_disk_name)
          end
        )

        tasks.push(
          Concurrent::Future.execute do
            ephemeral_disk_name = @disk_manager.generate_ephemeral_disk_name(vm_name)
            @disk_manager.delete_disk(storage_account_name, ephemeral_disk_name)
          end
        )

        # Cleanup invalid VM status file
        tasks.push(
          Concurrent::Future.execute do
            @disk_manager.delete_vm_status_files(storage_account_name, vm_name)
          end
        )
      end

      # when exception happens in thread, .wait will not raise the error, but .wait! will.
      # Calling .wait before .wait! to make sure that all tasks are completed.
      tasks.map(&:wait)
      tasks.map(&:wait!)
    end

    def reboot(instance_id)
      CPILogger.instance.logger.info("reboot(#{instance_id})")
      @azure_client.restart_virtual_machine(
        instance_id.resource_group_name,
        instance_id.vm_name
      )
    end

    def set_metadata(instance_id, metadata)
      CPILogger.instance.logger.info("set_metadata(#{instance_id}, #{metadata})")
      @azure_client.update_tags_of_virtual_machine(
        instance_id.resource_group_name,
        instance_id.vm_name,
        metadata.merge(AZURE_TAGS)
      )
    end

    ##
    # Attach a disk to the Vm
    #
    # @param [InstanceId] instance_id Instance id
    # @param [DiskId] disk_id disk id
    # @return [String] lun
    def attach_disk(instance_id, disk_id)
      CPILogger.instance.logger.info("attach_disk(#{instance_id}, #{disk_id})")
      disk_name = disk_id.disk_name
      disk_params = _get_disk_params(disk_id, instance_id.use_managed_disks?)
      lun = @azure_client.attach_disk_to_virtual_machine(
        instance_id.resource_group_name,
        instance_id.vm_name,
        disk_params
      )
      lun.to_s
    end

    def detach_disk(instance_id, disk_id)
      CPILogger.instance.logger.info("detach_disk(#{instance_id}, #{disk_id})")
      @azure_client.detach_disk_from_virtual_machine(
        instance_id.resource_group_name,
        instance_id.vm_name,
        disk_id.disk_name
      )
    end

    private

    def _build_instance_id(bosh_vm_meta, location, vm_props)
      if @use_managed_disks
        instance_id = VMInstanceId.create(vm_props.resource_group_name, bosh_vm_meta.agent_id)
      else
        storage_account = get_storage_account_from_vm_properties(vm_props, location)
        instance_id = VMInstanceId.create(vm_props.resource_group_name, bosh_vm_meta.agent_id, storage_account[:name])
      end
      instance_id
    end

    def _get_diagnostics_storage_account(location)
      @azure_config.enable_vm_boot_diagnostics && (@azure_config.environment != ENVIRONMENT_AZURESTACK) ? @storage_account_manager.get_or_create_diagnostics_storage_account(location) : nil
    end

    def _get_tags(vm_props)
      tags = AZURE_TAGS.dup
      custom_tags = vm_props.tags
      tags.merge!(custom_tags)
    end

    def _create_virtual_machine(instance_id, vm_params, network_interfaces, availability_set)
      resource_group_name = instance_id.resource_group_name
      vm_name = instance_id.vm_name
      max_retries = 2
      retry_create_count = 0
      begin
        @keep_failed_vms = false
        if availability_set.nil?
          @azure_client.create_virtual_machine(resource_group_name, vm_params, network_interfaces, nil)
        else
          availability_set_name = availability_set[:name]
          flock("#{CPI_LOCK_PREFIX_AVAILABILITY_SET}-#{availability_set_name}", File::LOCK_SH) do
            @azure_client.create_virtual_machine(resource_group_name, vm_params, network_interfaces, availability_set)
          end
        end
      rescue StandardError => e
        retry_create = false
        if e.instance_of?(AzureAsynchronousError) && e.status == PROVISIONING_STATE_FAILED
          if (retry_create_count += 1) <= max_retries
            CPILogger.instance.logger.info("create_virtual_machine - Retry #{retry_create_count}: will retry to create the virtual machine #{vm_name} which failed in provisioning")
            retry_create = true
          else
            # Keep the VM which fails in provisioning after multiple retries if "keep_failed_vms" is true in global configuration
            @keep_failed_vms = @azure_config.keep_failed_vms
          end
        end

        unless @keep_failed_vms
          retry_delete_count = 0
          begin
            CPILogger.instance.logger.info("create_virtual_machine - cleanup resources of the failed virtual machine #{vm_name} from resource group #{resource_group_name}. Retry #{retry_delete_count}.")

            if availability_set
              flock("#{CPI_LOCK_PREFIX_AVAILABILITY_SET}-#{availability_set[:name]}", File::LOCK_SH) do
                @azure_client.delete_virtual_machine(resource_group_name, vm_name)
              end
            else
              @azure_client.delete_virtual_machine(resource_group_name, vm_name)
            end

            if @use_managed_disks
              os_disk_name = @disk_manager2.generate_os_disk_name(vm_name)
              @disk_manager2.delete_disk(resource_group_name, os_disk_name)
            else
              storage_account_name = instance_id.storage_account_name
              os_disk_name = @disk_manager.generate_os_disk_name(vm_name)
              @disk_manager.delete_disk(storage_account_name, os_disk_name)

              # Cleanup invalid VM status file
              @disk_manager.delete_vm_status_files(storage_account_name, vm_name)
            end

            unless vm_params[:ephemeral_disk].nil?
              if @use_managed_disks
                ephemeral_disk_name = @disk_manager2.generate_ephemeral_disk_name(vm_name)
                @disk_manager2.delete_disk(resource_group_name, ephemeral_disk_name)
              else
                ephemeral_disk_name = @disk_manager.generate_ephemeral_disk_name(vm_name)
                @disk_manager.delete_disk(storage_account_name, ephemeral_disk_name)
              end
            end
          rescue StandardError => error
            retry if (retry_delete_count += 1) <= max_retries
            @keep_failed_vms = true # If the cleanup fails, then the VM resources have to be kept
            error_message = "The VM fails in provisioning.\n"
            error_message += "#{e.inspect}\n#{e.backtrace.join('\n')}\n\n"
            error_message += "And an error is thrown in cleanuping VM, os disk or ephemeral disk before retry.\n"
            error_message += "#{error.inspect}\n#{error.backtrace.join('\n')}"
            raise Bosh::Clouds::CloudError, error_message
          end
        end

        retry if retry_create

        raise e
      end
    end
  end
end