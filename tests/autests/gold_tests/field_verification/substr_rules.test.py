'''
Verify correct field verification behavior for contains, prefix, and suffix.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify correct field verification behavior for contains, prefix, and suffix.
'''

#
# Test 1: Verify field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/substr_rules.yaml")
server = r.AddServerProcess("server1", "replay_files/substr_rules.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "5", Field Name: "host", Required Value: "le.on", Value: "example.one"',
    'Validation should be happy that "le.on" is in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Success: Key: "5", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
    'Validation should be happy that "RequestData" began with "Req".')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Success: Key: "5", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
    'Validation should be happy that "It\'s there" ended with "there.')

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "5", Field Name: "host", Required Value: "two", Actual Value: "example.one"',
    'Validation should complain that "two" is not in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Violation: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "equest", Actual Value: "RequestData"',
    'Validation should complain that "RequestData" did not begin with "equest".')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Violation: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "er", Actual Value: "It\'s there"',
    'Validation should complain that "It\'s there" did not end with "er".')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "5", Field Name: "content-type", Required Value: "html", Value: "text/html"',
    'Validation should be happy that "html" is in "text/html".')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "5", Field Name: "set-cookie", Required Value: "ABCDE", Actual Value: "ABCD"',
    'Validation should complain that "ABCDE" is not in "ABCD".')

client.Streams.stdout += Testers.ContainsExpression(
    'Prefix Violation: Absent. Key: "5", Field Name: "x-not-a-header", Required Value: "Whatever"',
    'Validation should complain that "X-Not-A-Header" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
    'Suffix Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 2: Verify substring rules run against the RFC-combined value for repeated field lines.
#
r = Test.AddTestRun("Verify substring field verification works for repeated RFC-combinable fields")
client = r.AddClientProcess("client2", "replay_files/substr_rules_duplicate.yaml")
server = r.AddServerProcess("server2", "replay_files/substr_rules_duplicate.yaml")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "1", Field Name: "x-test-contains", Required Value: "alpha, beta", Value: "alpha, beta"',
    'Validation should be happy that repeated field lines are combined before contains checks.')

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "1", Field Name: "x-test-contains", Required Value: "gamma", Actual Value: "alpha, beta"',
    'Validation should complain that the combined field value does not contain "gamma".')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Success: Key: "1", Field Name: "x-test-prefix", Required Value: "start, e", Value: "start, end"',
    'Validation should be happy that prefix checks use the combined field value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Violation: Not Found. Key: "1", Field Name: "x-test-prefix", Required Value: "end", Actual Value: "start, end"',
    'Validation should complain that the combined field value does not begin with "end".')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Success: Key: "1", Field Name: "x-test-suffix", Required Value: "right", Value: "left, right"',
    'Validation should be happy that suffix checks use the combined field value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Violation: Not Found. Key: "1", Field Name: "x-test-suffix", Required Value: "left", Actual Value: "left, right"',
    'Validation should complain that the combined field value does not end with "left".')

client.ReturnCode = 0
server.ReturnCode = 1

#
# Test 3: Verify field verification using the map specification syntax.
#
r = Test.AddTestRun("Verify field verification works with the map specification syntax")
client = r.AddClientProcess("client3", "replay_files/map_specification.yaml")
server = r.AddServerProcess("server3", "replay_files/map_specification.yaml")
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "13", Field Name: "host", Required Value: "le.on", Value: "example.one"',
    'Validation should be happy that "le.on" is in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Success: Key: "13", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
    'Validation should be happy that "RequestData" began with "Req".')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Success: Key: "13", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
    'Validation should be happy that "It\'s there" ended with "there.')

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "13", Field Name: "host", Required Value: "two", Actual Value: "example.one"',
    'Validation should complain that "two" is not in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Prefix Violation: Not Found. Key: "13", Field Name: "x-test-request", Required Value: "equest", Actual Value: "RequestData"',
    'Validation should complain that "RequestData" did not begin with "equest".')

server.Streams.stdout += Testers.ContainsExpression(
    'Suffix Violation: Not Found. Key: "13", Field Name: "x-test-present", Required Value: "er", Actual Value: "It\'s there"',
    'Validation should complain that "It\'s there" did not end with "er".')

server.Streams.stdout += Testers.ContainsExpression(
    'Absence Success: Key: "13", Field Name: "x-test-absent"',
    'Validation should be happy that "X-Test-Absent" is not there.')

server.Streams.stdout += Testers.ContainsExpression(
    'Presence Success: Key: "13", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should be happy that "X-Test-Present" is there.')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "13", Field Name: "content-type", Required Value: "html", Value: "text/html"',
    'Validation should be happy that "html" is in "text/html".')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "13", Field Name: "set-cookie", Required Value: "ABCDE", Actual Value: "ABCD"',
    'Validation should complain that "ABCDE" is not in "ABCD".')

client.Streams.stdout += Testers.ContainsExpression(
    'Prefix Violation: Absent. Key: "13", Field Name: "x-not-a-header", Required Value: "Whatever"',
    'Validation should complain that "X-Not-A-Header" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Absent. Key: "13", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
    'Suffix Violation: Absent. Key: "13", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.ReturnCode = 1
server.ReturnCode = 1
