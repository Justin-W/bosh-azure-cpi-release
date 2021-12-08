# frozen_string_literal: true

module Bosh::AzureCloud
  ##
  # Represents Azure instance network config.
  #
  # VM can have up to 1 vip network attached to it.
  #
  # VM can have multiple network interfaces attached to it.
  # The VM size determines the number of NICs that you can create for a VM, please refer to
  # https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-linux-sizes/ for the max number of NICs for different VM size.
  # When there are multiple networks, you must have and only have 1 primary network specified. @networks[0] will be picked as the primary network.
  #

  class NetworkConfigurator
    include Helpers

    attr_reader :vip_network, :networks
    attr_accessor :logger

    ##
    # Creates new network spec
    #
    # networks[0] is always the primary network for the VM
    #
    # @param [Hash] azure_config global azure properties
    # @param [Hash] spec raw network spec passed by director
    def initialize(azure_config, spec)
      unless spec.is_a?(Hash)
        raise ArgumentError, 'Invalid spec, Hash expected, ' \
                             "'#{spec.class}' provided"
      end

      @logger = Bosh::Clouds::Config.logger
      @azure_config = azure_config
      @networks = []
      @vip_network = nil

      logger.debug "networks: '#{spec}'"
      spec.each_pair do |name, network_spec|
        network = nil
        network_type = network_spec['type'] || 'manual'

        case network_type
        when 'dynamic'
          network = DynamicNetwork.new(@azure_config, name, network_spec)

        when 'manual'
          network = ManualNetwork.new(@azure_config, name, network_spec)

        when 'vip'
          cloud_error("More than one vip network for '#{name}'") if @vip_network
          @vip_network = VipNetwork.new(@azure_config, name, network_spec)

        else
          cloud_error("Invalid network type '#{network_type}' for Azure, " \
                      "can only handle 'dynamic', 'vip', or 'manual' network types")
        end

        # TODO: issue-644: multi-AGW: Review: The following comment and code block seems to conflict with multiple code/doc comments elsewhere?
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/blob/f50122304c0bde85123612225a7244923027075b/src/bosh_azure_cpi/lib/cloud/azure/network/network_configurator.rb#L60-L67
        #       see also: https://bosh.io/docs/networks/#multi-homed
        #       see also: commit 5227c9d4fd238003fe4f116eb28535d89b5c98de
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/pull/200
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/blob/f50122304c0bde85123612225a7244923027075b/src/bosh_azure_cpi/lib/cloud/azure/restapi/azure_client.rb#L228
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/blob/f50122304c0bde85123612225a7244923027075b/src/bosh_azure_cpi/lib/cloud/azure/network/network_configurator.rb#L12
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/blob/f50122304c0bde85123612225a7244923027075b/src/bosh_azure_cpi/lib/cloud/azure/restapi/azure_client.rb#L305
        #       see also: https://github.com/cloudfoundry/bosh-azure-cpi-release/blob/f50122304c0bde85123612225a7244923027075b/src/bosh_azure_cpi/lib/cloud/azure/vms/vm_manager_network.rb#L185
        # @networks[0] is always the primary network.
        #
        # The network with 'default: ["gateway"]' will be the primary network.
        # For single network, 'default: ["gateway"]' can be ignored, it will automatically picked as primary network.
        #
        unless network.nil?
          if network.has_default_gateway?
            @networks.insert(0, network)
          else
            @networks.push(network)
          end
        end
      end

      cloud_error('At least one dynamic or manual network must be defined') if @networks.empty?
    end

    # For multiple networks, use the default dns specified in spec.
    # For single network, use its dns anyway.
    #
    def default_dns
      @networks.each do |network|
        return network.dns if network.has_default_dns?
      end
      @networks[0].dns
    end
  end
end
