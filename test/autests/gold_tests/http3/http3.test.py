'''
Verify basic HTTP/3 functionality.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic HTTP/3 functionality.
'''

#
# Test 1: Verify correct behavior of a single HTTP/3 transaction.
#
r = Test.AddTestRun("Verify HTTP/3")
client = r.AddClientProcess("client1", "replay_files/http3_to_http1.yaml")
server = r.AddServerProcess("server1", "replay_files/http3_to_http1.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http3_port,
                          server_port=server.Variables.http_port,
                          use_ssl=True, use_http3_to_1=True)

proxy.Streams.stdout = "gold/http3_to_http1_proxy.gold"
client.Streams.stdout = "gold/http3_to_http1_client.gold"
server.Streams.stdout = "gold/http3_to_http1_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

