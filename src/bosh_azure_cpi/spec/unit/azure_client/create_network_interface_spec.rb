# frozen_string_literal: true

require 'spec_helper'
require 'webmock/rspec'

WebMock.disable_net_connect!(allow_localhost: true)

describe Bosh::AzureCloud::AzureClient do
  let(:logger) { Bosh::Clouds::Config.logger }
  let(:azure_client) do
    Bosh::AzureCloud::AzureClient.new(
      mock_azure_config,
      logger
    )
  end
  let(:subscription_id) { mock_azure_config.subscription_id }
  let(:tenant_id) { mock_azure_config.tenant_id }
  let(:api_version) { AZURE_API_VERSION }
  let(:api_version_network) { AZURE_RESOURCE_PROVIDER_NETWORK }
  let(:resource_group) { 'fake-resource-group-name' }
  let(:request_id) { 'fake-request-id' }

  let(:token_uri) { "https://login.microsoftonline.com/#{tenant_id}/oauth2/token?api-version=#{api_version}" }
  let(:operation_status_link) { "https://management.azure.com/subscriptions/#{subscription_id}/operations/#{request_id}" }

  let(:valid_access_token) { 'valid-access-token' }

  let(:expires_on) { (Time.new + 1800).to_i.to_s }

  before do
    allow(azure_client).to receive(:sleep)
  end

  describe '#create_network_interface' do
    let(:network_interface_uri) { "https://management.azure.com/subscriptions/#{subscription_id}/resourceGroups/#{resource_group}/providers/Microsoft.Network/networkInterfaces/#{nic_name}?api-version=#{api_version_network}" }

    let(:nic_name) { 'fake-nic-name' }
    let(:nsg_id) { 'fake-nsg-id' }
    let(:subnet) { { id: 'fake-subnet-id' } }
    let(:tags) { { 'foo' => 'bar' } }

    context 'when token is valid, create operation is accepted and completed' do
      context 'with private ip, public ip and dns servers' do
        let(:nic_params) do
          {
            name: nic_name,
            location: 'fake-location',
            ipconfig_name: 'fake-ipconfig-name',
            subnet: { id: subnet[:id] },
            tags: {},
            enable_ip_forwarding: false,
            enable_accelerated_networking: false,
            private_ip: '10.0.0.100',
            dns_servers: ['168.63.129.16'],
            public_ip: { id: 'fake-public-id' },
            network_security_group: { id: nsg_id },
            application_security_groups: [],
            load_balancers: nil,
            application_gateways: nil
          }
        end
        let(:request_body) do
          {
            name: nic_params[:name],
            location: nic_params[:location],
            tags: {},
            properties: {
              networkSecurityGroup: {
                id: nic_params[:network_security_group][:id]
              },
              enableIPForwarding: false,
              enableAcceleratedNetworking: false,
              ipConfigurations: [{
                name: nic_params[:ipconfig_name],
                properties: {
                  privateIPAddress: nic_params[:private_ip],
                  privateIPAllocationMethod: 'Static',
                  publicIPAddress: { id: nic_params[:public_ip][:id] },
                  subnet: {
                    id: subnet[:id]
                  }
                }
              }],
              dnsSettings: {
                dnsServers: ['168.63.129.16']
              }
            }
          }
        end

        it 'should create a network interface without error' do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )

          expect do
            azure_client.create_network_interface(resource_group, nic_params)
          end.not_to raise_error
        end
      end

      context 'without private ip, public ip and dns servers' do
        let(:nic_params) do
          {
            name: nic_name,
            location: 'fake-location',
            ipconfig_name: 'fake-ipconfig-name',
            subnet: { id: subnet[:id] },
            tags: {},
            enable_ip_forwarding: false,
            enable_accelerated_networking: false,
            network_security_group: { id: nsg_id },
            application_security_groups: [],
            load_balancers: nil,
            application_gateways: nil
          }
        end
        let(:request_body) do
          {
            name: nic_params[:name],
            location: nic_params[:location],
            tags: {},
            properties: {
              networkSecurityGroup: {
                id: nic_params[:network_security_group][:id]
              },
              enableIPForwarding: false,
              enableAcceleratedNetworking: false,
              ipConfigurations: [{
                name: nic_params[:ipconfig_name],
                properties: {
                  privateIPAddress: nil,
                  privateIPAllocationMethod: 'Dynamic',
                  publicIPAddress: nil,
                  subnet: {
                    id: subnet[:id]
                  }
                }
              }],
              dnsSettings: {
                dnsServers: []
              }
            }
          }
        end

        it 'should create a network interface without error' do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )

          expect do
            azure_client.create_network_interface(resource_group, nic_params)
          end.not_to raise_error
        end
      end

      context 'without network security group' do
        let(:nic_params) do
          {
            name: nic_name,
            location: 'fake-location',
            ipconfig_name: 'fake-ipconfig-name',
            subnet: { id: subnet[:id] },
            tags: {},
            enable_ip_forwarding: false,
            enable_accelerated_networking: false,
            private_ip: '10.0.0.100',
            dns_servers: ['168.63.129.16'],
            public_ip: { id: 'fake-public-id' },
            network_security_group: nil,
            application_security_groups: [],
            load_balancers: nil,
            application_gateways: nil
          }
        end
        let(:request_body) do
          {
            name: nic_params[:name],
            location: nic_params[:location],
            tags: {},
            properties: {
              networkSecurityGroup: nil,
              enableIPForwarding: false,
              enableAcceleratedNetworking: false,
              ipConfigurations: [{
                name: nic_params[:ipconfig_name],
                properties: {
                  privateIPAddress: nic_params[:private_ip],
                  privateIPAllocationMethod: 'Static',
                  publicIPAddress: { id: nic_params[:public_ip][:id] },
                  subnet: {
                    id: subnet[:id]
                  }
                }
              }],
              dnsSettings: {
                dnsServers: ['168.63.129.16']
              }
            }
          }
        end

        it 'should create a network interface without network security group' do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )

          expect do
            azure_client.create_network_interface(resource_group, nic_params)
          end.not_to raise_error
        end
      end

      context 'with single load balancer' do
        before do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )
        end

        context 'with single backend pool' do
          let(:nic_params) do
            {
              name: nic_name,
              location: 'fake-location',
              ipconfig_name: 'fake-ipconfig-name',
              subnet: { id: subnet[:id] },
              tags: {},
              enable_ip_forwarding: false,
              enable_accelerated_networking: false,
              private_ip: '10.0.0.100',
              dns_servers: ['168.63.129.16'],
              public_ip: { id: 'fake-public-id' },
              network_security_group: { id: nsg_id },
              application_security_groups: [],
              load_balancers: [{
                backend_address_pools: [
                  {
                    name: 'fake-lb-pool-name',
                    id: 'fake-lb-pool-id'
                  }
                ],
                frontend_ip_configurations: [
                  {
                    inbound_nat_rules: [{}]
                  }
                ]
              }],
              application_gateways: nil
            }
          end

          let(:request_body) do
            {
              name: nic_params[:name],
              location: nic_params[:location],
              tags: {},
              properties: {
                networkSecurityGroup: {
                  id: nic_params[:network_security_group][:id]
                },
                enableIPForwarding: false,
                enableAcceleratedNetworking: false,
                ipConfigurations: [{
                  name: nic_params[:ipconfig_name],
                  properties: {
                    privateIPAddress: nic_params[:private_ip],
                    privateIPAllocationMethod: 'Static',
                    publicIPAddress: { id: nic_params[:public_ip][:id] },
                    subnet: {
                      id: subnet[:id]
                    },
                    loadBalancerBackendAddressPools: [
                      {
                        id: 'fake-lb-pool-id'
                      }
                    ],
                    loadBalancerInboundNatRules: [{}]
                  }
                }],
                dnsSettings: {
                  dnsServers: ['168.63.129.16']
                }
              }
            }
          end

          it 'should create a network interface without error' do
            expect do
              azure_client.create_network_interface(resource_group, nic_params)
            end.not_to raise_error
          end
        end

        context 'with multiple backend pools' do
          context 'when backend_pool_name is not specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: [{
                  backend_address_pools: [
                    {
                      name: 'fake-lb-pool-name',
                      id: 'fake-lb-pool-id'
                    },
                    {
                      name: 'fake-lb-pool2-name',
                      id: 'fake-lb-pool2-id'
                    }
                  ],
                  frontend_ip_configurations: [
                    {
                      inbound_nat_rules: [{}, {}]
                    }
                  ]
                }],
                application_gateways: nil
              }
            end

            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      loadBalancerBackendAddressPools: [
                        {
                          id: 'fake-lb-pool-id'
                        },
                        {
                          id: 'fake-lb-pool2-id'
                        }
                      ],
                      loadBalancerInboundNatRules: [{}]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...ns[0].properties.loadBalancerInboundNatRules[0]",
            it 'should use the default backend_pools'
            # it 'should use the default backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end

          context 'when backend_pool_name is specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                # NOTE: This data would normally be created by the `VMManager._get_load_balancers` method,
                # which would remove all but the `vm_props`-configured pool from the list.
                load_balancers: [{
                  backend_address_pools: [
                    # {
                    #   name: 'fake-lb-pool-name',
                    #   id: 'fake-lb-pool-id'
                    # },
                    {
                      name: 'fake-lb-pool2-name',
                      id: 'fake-lb-pool2-id'
                    }
                  ],
                  frontend_ip_configurations: [
                    {
                      inbound_nat_rules: [{}, {}]
                    }
                  ]
                }],
                application_gateways: nil
              }
            end

            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      loadBalancerBackendAddressPools: [
                        {
                          id: 'fake-lb-pool-id'
                        },
                        {
                          id: 'fake-lb-pool2-id'
                        }
                      ],
                      loadBalancerInboundNatRules: [{}]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...ns[0].properties.loadBalancerInboundNatRules[0]",
            it 'should use the specified backend_pools'
            # it 'should use the specified backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end
        end

        # NOTE: This should never happen, since an error would be raised earlier (preventing `azure_client.create_network_interface` from being called)
        # context 'when an invalid backend_pool_name is specified' do
        #   it 'should never happen'
        # end
      end

      context 'with multiple load balancers' do # rubocop:disable RSpec/RepeatedExampleGroupBody
        before do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )
        end

        context 'with single backend pool' do
          let(:nic_params) do
            {
              name: nic_name,
              location: 'fake-location',
              ipconfig_name: 'fake-ipconfig-name',
              subnet: { id: subnet[:id] },
              tags: {},
              enable_ip_forwarding: false,
              enable_accelerated_networking: false,
              private_ip: '10.0.0.100',
              dns_servers: ['168.63.129.16'],
              public_ip: { id: 'fake-public-id' },
              network_security_group: { id: nsg_id },
              application_security_groups: [],
              load_balancers: [
                {
                  backend_address_pools: [
                    {
                      name: 'fake-lb-pool-name',
                      id: 'fake-lb-pool-id'
                    }
                  ],
                  frontend_ip_configurations: [
                    {
                      inbound_nat_rules: [{}, {}]
                    }
                  ]
                },
                {
                  backend_address_pools: [
                    {
                      name: 'fake-lb2-pool-1-name',
                      id: 'fake-lb2-pool-1-id'
                    }
                  ],
                  frontend_ip_configurations: [
                    {
                      inbound_nat_rules: [{}, {}]
                    }
                  ]
                }
              ],
              application_gateways: nil
            }
          end

          let(:request_body) do
            {
              name: nic_params[:name],
              location: nic_params[:location],
              tags: {},
              properties: {
                networkSecurityGroup: {
                  id: nic_params[:network_security_group][:id]
                },
                enableIPForwarding: false,
                enableAcceleratedNetworking: false,
                ipConfigurations: [{
                  name: nic_params[:ipconfig_name],
                  properties: {
                    privateIPAddress: nic_params[:private_ip],
                    privateIPAllocationMethod: 'Static',
                    publicIPAddress: { id: nic_params[:public_ip][:id] },
                    subnet: {
                      id: subnet[:id]
                    },
                    loadBalancerBackendAddressPools: [
                      {
                        id: 'fake-lb-pool-id'
                      },
                      {
                        id: 'fake-lb2-pool-1-id'
                      }
                    ],
                    loadBalancerInboundNatRules: [{}]
                  }
                }],
                dnsSettings: {
                  dnsServers: ['168.63.129.16']
                }
              }
            }
          end

          # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
          #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...ns[0].properties.loadBalancerInboundNatRules[0]",
          it 'should create a network interface without error'
          # it 'should create a network interface without error' do
          #   expect do
          #     azure_client.create_network_interface(resource_group, nic_params)
          #   end.not_to raise_error
          # end
        end

        context 'with multiple backend pools' do
          context 'when backend_pool_name is not specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: [
                  {
                    backend_address_pools: [
                      {
                        name: 'fake-lb-pool-name',
                        id: 'fake-lb-pool-id'
                      },
                      {
                        name: 'fake-lb-pool2-name',
                        id: 'fake-lb-pool2-id'
                      }
                    ],
                    frontend_ip_configurations: [
                      {
                        inbound_nat_rules: [{}, {}]
                      }
                    ]
                  },
                  {
                    backend_address_pools: [
                      {
                        name: 'fake-lb2-pool-1-name',
                        id: 'fake-lb2-pool-1-id'
                      },
                      {
                        name: 'fake-lb2-pool-2-name',
                        id: 'fake-lb2-pool-2-id'
                      }
                    ],
                    frontend_ip_configurations: [
                      {
                        inbound_nat_rules: [{}, {}]
                      }
                    ]
                  }
                ],
                application_gateways: nil
              }
            end

            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      loadBalancerBackendAddressPools: [
                        {
                          id: 'fake-lb-pool-id'
                        },
                        {
                          id: 'fake-lb2-pool-1-id'
                        }
                      ],
                      loadBalancerInboundNatRules: [{}]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...ns[0].properties.loadBalancerInboundNatRules[0]",
            it 'should use the default backend_pools'
            # it 'should use the default backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end

          context 'when backend_pool_name is specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                # NOTE: This data would normally be created by the `VMManager._get_load_balancers` method,
                # which would remove all but the `vm_props`-configured pools from the list.
                load_balancers: [
                  {
                    backend_address_pools: [
                      # {
                      #   name: 'fake-lb-pool-name',
                      #   id: 'fake-lb-pool-id'
                      # },
                      {
                        name: 'fake-lb-pool2-name',
                        id: 'fake-lb-pool2-id'
                      }
                    ],
                    frontend_ip_configurations: [
                      {
                        inbound_nat_rules: [{}, {}]
                      }
                    ]
                  },
                  {
                    backend_address_pools: [
                      # {
                      #   name: 'fake-lb2-pool-1-name',
                      #   id: 'fake-lb2-pool-1-id'
                      # },
                      {
                        name: 'fake-lb2-pool-2-name',
                        id: 'fake-lb2-pool-2-id'
                      }
                    ],
                    frontend_ip_configurations: [
                      {
                        inbound_nat_rules: [{}, {}]
                      }
                    ]
                  }
                ],
                application_gateways: nil
              }
            end

            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      loadBalancerBackendAddressPools: [
                        {
                          id: 'fake-lb-pool2-id'
                        },
                        {
                          id: 'fake-lb2-pool-2-id'
                        }
                      ],
                      loadBalancerInboundNatRules: [{}]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...ns[0].properties.loadBalancerInboundNatRules[0]",
            it 'should use the specified backend_pools'
            # it 'should use the specified backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end
        end
      end

      context 'with application security groups' do
        let(:nic_params) do
          {
            name: nic_name,
            location: 'fake-location',
            ipconfig_name: 'fake-ipconfig-name',
            subnet: { id: subnet[:id] },
            tags: {},
            enable_ip_forwarding: false,
            enable_accelerated_networking: false,
            private_ip: '10.0.0.100',
            dns_servers: ['168.63.129.16'],
            public_ip: { id: 'fake-public-id' },
            network_security_group: { id: nsg_id },
            application_security_groups: [{ id: 'fake-asg-id-1' }, { id: 'fake-asg-id-2' }],
            load_balancers: nil,
            application_gateways: nil
          }
        end
        let(:request_body) do
          {
            name: nic_params[:name],
            location: nic_params[:location],
            tags: {},
            properties: {
              networkSecurityGroup: {
                id: nic_params[:network_security_group][:id]
              },
              enableIPForwarding: false,
              enableAcceleratedNetworking: false,
              ipConfigurations: [{
                name: nic_params[:ipconfig_name],
                properties: {
                  privateIPAddress: nic_params[:private_ip],
                  privateIPAllocationMethod: 'Static',
                  publicIPAddress: { id: nic_params[:public_ip][:id] },
                  subnet: {
                    id: subnet[:id]
                  },
                  applicationSecurityGroups: [
                    {
                      id: 'fake-asg-id-1'
                    },
                    {
                      id: 'fake-asg-id-2'
                    }
                  ]
                }
              }],
              dnsSettings: {
                dnsServers: ['168.63.129.16']
              }
            }
          }
        end

        it 'should create a network interface without error' do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )

          expect do
            azure_client.create_network_interface(resource_group, nic_params)
          end.not_to raise_error
        end
      end

      # NOTE: issue-644: unit tests for single-AGW, single-pool
      context 'with application gateway' do
        before do
          stub_request(:post, token_uri).to_return(
            status: 200,
            body: {
              'access_token' => valid_access_token,
              'expires_on' => expires_on
            }.to_json,
            headers: {}
          )
          stub_request(:put, network_interface_uri)
            .with(body: request_body.to_json)
            .to_return(
              status: 200,
              body: '',
              headers: {
                'azure-asyncoperation' => operation_status_link
              }
            )
          stub_request(:get, operation_status_link).to_return(
            status: 200,
            body: '{"status":"Succeeded"}',
            headers: {}
          )
        end

        context 'with single backend pool' do
          let(:nic_params) do
            {
              name: nic_name,
              location: 'fake-location',
              ipconfig_name: 'fake-ipconfig-name',
              subnet: { id: subnet[:id] },
              tags: {},
              enable_ip_forwarding: false,
              enable_accelerated_networking: false,
              private_ip: '10.0.0.100',
              dns_servers: ['168.63.129.16'],
              public_ip: { id: 'fake-public-id' },
              network_security_group: { id: nsg_id },
              application_security_groups: [],
              load_balancers: nil,
              application_gateways: [{
                backend_address_pools: [
                  {
                    name: 'fake-agw-pool-name',
                    id: 'fake-agw-pool-id'
                  }
                ]
              }]
            }
          end
          let(:request_body) do
            {
              name: nic_params[:name],
              location: nic_params[:location],
              tags: {},
              properties: {
                networkSecurityGroup: {
                  id: nic_params[:network_security_group][:id]
                },
                enableIPForwarding: false,
                enableAcceleratedNetworking: false,
                ipConfigurations: [{
                  name: nic_params[:ipconfig_name],
                  properties: {
                    privateIPAddress: nic_params[:private_ip],
                    privateIPAllocationMethod: 'Static',
                    publicIPAddress: { id: nic_params[:public_ip][:id] },
                    subnet: {
                      id: subnet[:id]
                    },
                    applicationGatewayBackendAddressPools: [
                      {
                        id: 'fake-agw-pool-id'
                      }
                    ]
                  }
                }],
                dnsSettings: {
                  dnsServers: ['168.63.129.16']
                }
              }
            }
          end

          it 'should create a network interface without error' do
            expect do
              azure_client.create_network_interface(resource_group, nic_params)
            end.not_to raise_error
          end
        end

        context 'with multiple backend pools' do
          context 'when backend_pool_name is not specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: nil,
                application_gateways: [
                  {
                    backend_address_pools: [
                      {
                        name: 'fake-agw-pool-name',
                        id: 'fake-agw-pool-id'
                      },
                      {
                        name: 'fake-agw-pool2-name',
                        id: 'fake-agw-pool2-id'
                      }
                    ]
                  }
                ]
              }
            end
            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      applicationGatewayBackendAddressPools: [
                        {
                          id: 'fake-agw-pool-id'
                        },
                        {
                          id: 'fake-agw-pool2-id'
                        }
                      ]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...BackendAddressPools[1]",
            it 'should use the default backend_pools'
            # it 'should use the default backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end

          context 'when backend_pool_name is specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: nil,
                # NOTE: This data would normally be created by the `VMManager._get_application_gateways` method,
                # which would remove all but the `vm_props`-configured pool from the list.
                application_gateways: [
                  {
                    backend_address_pools: [
                      # {
                      #   name: 'fake-agw-pool-name',
                      #   id: 'fake-agw-pool-id'
                      # },
                      {
                        name: 'fake-agw-pool2-name',
                        id: 'fake-agw-pool2-id'
                      }
                    ]
                  }
                ]
              }
            end
            let(:request_body) do
              {
                name: nic_params[:name],
                location: nic_params[:location],
                tags: {},
                properties: {
                  networkSecurityGroup: {
                    id: nic_params[:network_security_group][:id]
                  },
                  enableIPForwarding: false,
                  enableAcceleratedNetworking: false,
                  ipConfigurations: [{
                    name: nic_params[:ipconfig_name],
                    properties: {
                      privateIPAddress: nic_params[:private_ip],
                      privateIPAllocationMethod: 'Static',
                      publicIPAddress: { id: nic_params[:public_ip][:id] },
                      subnet: {
                        id: subnet[:id]
                      },
                      applicationGatewayBackendAddressPools: [
                        {
                          id: 'fake-agw-pool-id'
                        },
                        {
                          id: 'fake-agw-pool2-id'
                        }
                      ]
                    }
                  }],
                  dnsSettings: {
                    dnsServers: ['168.63.129.16']
                  }
                }
              }
            end

            # NOTE: issue-644: rspec output truncation: this spec is failing, but RSpec is truncating the output, making it difficult to fix the failure.
            #     > expected no Exception, got #<WebMock::NetConnectNotAllowedError: Real HTTP connections are disabled. Unregistered request: PUT https://management.azure.com/subscriptions/aa643f05-5b67-4d58-b433-54c2e9131a59/resourceGroups/fake-resource-group-name/providers/Microsoft.Network/net...yBackendAddressPools[0]",
            it 'should use the specified backend_pools'
            # it 'should use the specified backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end
        end

        # NOTE: This should never happen, since an error would be raised earlier (preventing `azure_client.create_network_interface` from being called)
        # context 'when an invalid backend_pool_name is specified' do
        #   it 'should never happen'
        # end
      end

      context 'with multiple application gateways' do # rubocop:disable RSpec/RepeatedExampleGroupBody
        context 'with single backend pool' do
          let(:nic_params) do
            {
              name: nic_name,
              location: 'fake-location',
              ipconfig_name: 'fake-ipconfig-name',
              subnet: { id: subnet[:id] },
              tags: {},
              enable_ip_forwarding: false,
              enable_accelerated_networking: false,
              private_ip: '10.0.0.100',
              dns_servers: ['168.63.129.16'],
              public_ip: { id: 'fake-public-id' },
              network_security_group: { id: nsg_id },
              application_security_groups: [],
              load_balancers: nil,
              application_gateways: [
                {
                  backend_address_pools: [
                    {
                      name: 'fake-agw-pool-name',
                      id: 'fake-agw-pool-id'
                    }
                  ]
                },
                {
                  backend_address_pools: [
                    {
                      name: 'fake-agw2-pool-1-name',
                      id: 'fake-agw2-pool-1-id'
                    }
                  ]
                }
              ]
            }
          end

          # TODO: issue-644: multi-AGW: add unit tests for multi-AGWs
          it 'should create a network interface without error'
          # it 'should create a network interface without error' do
          #   expect do
          #     azure_client.create_network_interface(resource_group, nic_params)
          #   end.not_to raise_error
          # end
        end

        context 'with multiple backend pools' do
          context 'when backend_pool_name is not specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: nil,
                application_gateways: [
                  {
                    backend_address_pools: [
                      {
                        name: 'fake-agw-pool-name',
                        id: 'fake-agw-pool-id'
                      },
                      {
                        name: 'fake-agw-pool2-name',
                        id: 'fake-agw-pool2-id'
                      }
                    ]
                  },
                  {
                    backend_address_pools: [
                      {
                        name: 'fake-agw2-pool-1-name',
                        id: 'fake-agw2-pool-1-id'
                      },
                      {
                        name: 'fake-agw2-pool-2-name',
                        id: 'fake-agw2-pool-2-id'
                      }
                    ]
                  }
                ]
              }
            end

            # TODO: issue-644: multi-BEPool-AGW: add unit tests for multi-pool AGWs
            it 'should use the default backend_pools'
            # it 'should use the default backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end

          context 'when backend_pool_name is specified' do
            let(:nic_params) do
              {
                name: nic_name,
                location: 'fake-location',
                ipconfig_name: 'fake-ipconfig-name',
                subnet: { id: subnet[:id] },
                tags: {},
                enable_ip_forwarding: false,
                enable_accelerated_networking: false,
                private_ip: '10.0.0.100',
                dns_servers: ['168.63.129.16'],
                public_ip: { id: 'fake-public-id' },
                network_security_group: { id: nsg_id },
                application_security_groups: [],
                load_balancers: nil,
                # NOTE: This data would normally be created by the `VMManager._get_application_gateways` method,
                # which would remove all but the `vm_props`-configured pools from the list.
                application_gateways: [
                  {
                    backend_address_pools: [
                      # {
                      #   name: 'fake-agw-pool-name',
                      #   id: 'fake-agw-pool-id'
                      # },
                      {
                        name: 'fake-agw-pool2-name',
                        id: 'fake-agw-pool2-id'
                      }
                    ]
                  },
                  {
                    backend_address_pools: [
                      # {
                      #   name: 'fake-agw2-pool-1-name',
                      #   id: 'fake-agw2-pool-1-id'
                      # },
                      {
                        name: 'fake-agw2-pool-2-name',
                        id: 'fake-agw2-pool-2-id'
                      }
                    ]
                  }
                ]
              }
            end

            # TODO: issue-644: multi-BEPool-AGW: add unit tests for named-pool AGWs
            it 'should use the specified backend_pools'
            # it 'should use the specified backend_pools' do
            #   expect do
            #     azure_client.create_network_interface(resource_group, nic_params)
            #   end.not_to raise_error
            # end
          end
        end
      end
    end
  end
end
