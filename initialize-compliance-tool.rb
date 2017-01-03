#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'json'

bridge_url = ENV.fetch('BRIDGE_URL', 'http://localhost:50400')
compliance_tool_url = URI('https://compliance-tool-reference.ida.digital.cabinet-office.gov.uk/idp-test-run')
compliance_tool_settings = {
    idpEntityId: "#{bridge_url}/metadata",
    singleSignOnServiceUrl: "#{bridge_url}/SAML2/SSO/POST",
    idpPublicCert: 'MIIEXDCCA0SgAwIBAgIQPPGZJz53HfQBT8cWHAnrSzANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJHQjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEVMBMGA1UEAxMMSURBUCBUZXN0IENBMB4XDTE2MTIxMjAwMDAwMFoXDTE3MTIxMjIzNTk1OVowgZIxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZMb25kb24xDzANBgNVBAcTBkxvbmRvbjEXMBUGA1UEChQOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsUA0dEUzE6MDgGA1UEAxMxVmVyaWZ5IGVJREFTIEJyaWRnZSBTaWduaW5nIERlbW8gKDIwMTYxMjEyMTIwNzQ3KTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQmVEUsLWJFL77pWifDCM3kAjXC6Xumx07Ehng+jxYoQeNowhTBrLSrnwCG6QDK1bxXq1yMVfgswlECquDih70oP6BTZ76P0dmaywWJaQ9S9jr+7QDVjH8MZsssLtrfIUCQ0h27n/fOoRDecY+BzJ757qSxQ3pKdQIDP48scKOsAB071ZvawvZ8aLWjJYx12dhcouYWf6r4/A6RsrIwAom6J/z8x56Zg98vScRtFmk08xdfjKgyxaNsw/6D01lUO1EA65Jt/TsSGxsBGYef1mQQpqS6qxe6egEV9lQ7MdvLru6WdoJNH5zUo3hvmgiGA0qhhp2eyTjvmyorlbN9je0CAwEAAaOB8zCB8DAMBgNVHRMBAf8EAjAAMFUGA1UdHwROMEwwSqBIoEaGRGh0dHA6Ly9vbnNpdGVjcmwudHJ1c3R3aXNlLmNvbS9DYWJpbmV0T2ZmaWNlSURBUFRlc3RDQS9MYXRlc3RDUkwuY3JsMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU8qM7ztLls93rvx+gd1JiFKNE8XwwHwYDVR0jBBgwFoAUahFNZFDf3mNvV6GIH/gDlQ4iBLQwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vc3RkLW9jc3AudHJ1c3R3aXNlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAMdTC77YxMTJ8VsSzyKW+zTyyOIW4dEi2Ojz3mE+V81ziwS3Qe19+P8NlPTikRUGDB0KUAmTPBieeFl4HQyuOY4ouEASRDWgis2LG8AlpGGwJHF3cuPoQiDv1nO25Xtjo5RZH6zpvmPguXBb41jrpooY8qlwhEMKgvRu5JQNmUUjuA61nNQbi/ZL4aCLxFPbNR9UzAdFyXXjb33zb9IxArBYVbX14eiAr2Yihsp5BFn7110QlCQoqLLW7+JkUPPzOuTlQc98BsN7MgoSFyTe+I8GHGOX9W4II9J8aAaIp2h24w9ldKkePOygEAJlRnOnZOSFsliuB0kA7fMTzEKLsyg=='
}

compliance_tool_request = Net::HTTP::Post.new(compliance_tool_url.path, 'Content-Type' => 'application/json')
compliance_tool_request.body = compliance_tool_settings.to_json
compliance_tool_response = Net::HTTP.start(compliance_tool_url.hostname, compliance_tool_url.port, use_ssl: compliance_tool_url.scheme == 'https') { |http|
  http.request(compliance_tool_request)
}

puts compliance_tool_response.header.fetch('location')

