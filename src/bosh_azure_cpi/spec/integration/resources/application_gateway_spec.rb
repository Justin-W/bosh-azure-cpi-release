# frozen_string_literal: true

require 'integration/spec_helper'

describe Bosh::AzureCloud::Cloud do
  before(:all) do
    @application_gateway_name = ENV.fetch('BOSH_AZURE_APPLICATION_GATEWAY_NAME') # 'azure_application_gateway'
    @application_gateway_backend_pool_name = ENV.fetch('BOSH_AZURE_APPLICATION_GATEWAY_BACKEND_POOL_NAME') # 'appGatewayBackendPool'
  end

  let(:network_spec) do
    {
      'network_a' => {
        'type' => 'manual',
        'ip' => "10.0.0.#{Random.rand(10..99)}",
        'cloud_properties' => {
          'virtual_network_name' => @vnet_name,
          'subnet_name' => @subnet_name
        }
      }
    }
  end

  let(:threads) { 2 }
  let(:ip_address_start) do
    Random.rand(10..(100 - threads))
  end
  let(:ip_address_end) do
    ip_address_start + threads - 1
  end
  let(:ip_address_specs) do
    (ip_address_start..ip_address_end).to_a.collect { |x| "10.0.0.#{x}" }
  end
  let(:network_specs) do
    ip_address_specs.collect do |ip_address_spec|
      {
        'network_a' => {
          'type' => 'manual',
          'ip' => ip_address_spec,
          'cloud_properties' => {
            'virtual_network_name' => @vnet_name,
            'subnet_name' => @subnet_name
          }
        }
      }
    end
  end

  # NOTE: issue-644: integration tests for original `application_gateway` config (single-AGW, unspecified-pool)
  context 'when application_gateway is specified in resource pool' do
    let(:vm_properties) do
      {
        'instance_type' => @instance_type,
        'application_gateway' => @application_gateway_name
      }
    end

    it 'should add the VM to the default backend pool of application gateway' do
      ag_url = get_azure_client.rest_api_url(
        Bosh::AzureCloud::AzureClient::REST_API_PROVIDER_NETWORK,
        Bosh::AzureCloud::AzureClient::REST_API_APPLICATION_GATEWAYS,
        name: @application_gateway_name
      )

      lifecycles = []
      threads.times do |i|
        lifecycles[i] = Thread.new do
          agent_id = SecureRandom.uuid
          ip_config_id = "/subscriptions/#{@subscription_id}/resourceGroups/#{@default_resource_group_name}/providers/Microsoft.Network/networkInterfaces/#{agent_id}-0/ipConfigurations/ipconfig0"
          begin
            new_instance_id = @cpi.create_vm(
              agent_id,
              @stemcell_id,
              vm_properties,
              network_specs[i]
            )
            ag = get_azure_client.get_resource_by_id(ag_url)
            expect(ag['properties']['backendAddressPools'][0]['properties']['backendIPConfigurations']).to include(
              'id' => ip_config_id
            )
          ensure
            @cpi.delete_vm(new_instance_id) if new_instance_id
          end
          ag = get_azure_client.get_resource_by_id(ag_url)
          unless ag['properties']['backendAddressPools'][0]['properties']['backendIPConfigurations'].nil?
            expect(ag['properties']['backendAddressPools'][0]['properties']['backendIPConfigurations']).not_to include(
              'id' => ip_config_id
            )
          end
        end
      end
      lifecycles.each(&:join)
    end
  end

  # NOTE: issue-644: integration tests for new `application_gateways` config (1 AGWs, 0+ pools)
  context 'when application_gateways is specified in resource pool' do
    # NOTE: issue-644: integration tests for new `application_gateways` config (1 AGWs, default pool)
    context 'when application_gateways/backend_pool is not specified' do
      let(:vm_properties) do
        {
          'instance_type' => @instance_type,
          'application_gateways' => [
            {
              'name' => @application_gateway_name
              # 'backend_pool' => @application_gateway_backend_pool_name,
            }
          ]
        }
      end

      # TODO: issue-644: multi-AGW: add integration tests for multi-AGWs
      it 'should add the VM to the first backend pool of application gateway'
    end

    # NOTE: issue-644: integration tests for new `application_gateways` config (1 AGWs, 1 explicitly-named pool)
    context 'when application_gateways/backend_pool is specified' do
      let(:vm_properties) do
        {
          'instance_type' => @instance_type,
          'application_gateways' => [
            {
              'name' => @application_gateway_name,
              'backend_pool' => @application_gateway_backend_pool_name
            }
          ]
        }
      end

      # TODO: issue-644: multi-AGW: add integration tests for multi-AGWs
      # TODO: issue-644: multi-BEPool-AGW: add integration tests for multi-pool AGWs
      it 'should add the VM to the specified backend pool of application gateway'
    end

    # NOTE: issue-644: adding integration tests for the new `application_gateways` config with 2+ AGWs and/or 1+ AGWs with 2+ backend pools would require modification (and/or separate, alternate versions) of the integration test setup scripts, assets, etc. files.
    # see: ci/assets/terraform/integration/template.tf
    # see: ci/tasks/run-integration.sh
    # see: ci/tasks/run-integration-windows.sh
  end
end
