'''
Verify correct field verification behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify correct field verification behavior.
'''

#
# Test 1: Verify field verification in a JSON replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/various_verification.json")
server = r.AddServerProcess("server1", "replay_files/various_verification.json")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

# Verify a success and failure of each validation in the request.
server.Streams.stdout = Testers.ContainsExpression(
    'Absence Success: Key: "1", Field Name: "x-candy"',
    'Validation should be happy that the proxy removed X-CANDY.')
server.Streams.stdout += Testers.ContainsExpression(
    'Absence Violation: Present. Key: "1", Field Name: "content-type", Value: "application/octet-stream"',
    'Validation should complain that "content-type" is present')
server.Streams.stdout += Testers.ContainsExpression(
    'Presence Success: Key: "1", Field Name: "content-length", Value: "399"',
    'Validation should be happy that "content-length" is present.')
server.Streams.stdout += Testers.ContainsExpression(
    'Presence Success: Key: "1", Field Name: "exampleremoteip", Value: "10.10.10.4"',
    'Validation should be happy that "ExampleRemoteIP" is present even though its value differs.')
server.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. Key: "1", Field Name: "client-ip"',
    'Validation should complain that "client-ip" is misssing')
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "x-someid", Value: "21djfk39jfkds"',
    'Validation should be happy that "S-SomeId" has the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "1", Field Name: "host", Correct Value: "example.com", Actual Value: "test.example.com"',
    'Validation should complain that the "Host" value differs from the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "1", Field Name: "x-test-case", Correct Value: "CASEmatters", Actual Value: "caseMATTERS"',
    'Equals validation must be case-sensitive.')

# Verify a success and failure of each validation in the response.
client.Streams.stdout = Testers.ContainsExpression(
    'Absence Success: Key: "1", Field Name: "x-newtestheader"',
    'Validation should be happy that the proxy removed X-NewTestHeader.')
client.Streams.stdout += Testers.ContainsExpression(
    'Absence Violation: Present. Key: "1", Field Name: "x-shouldexist", Value: "trustme; it=will"',
    'Validation should complain that "X-ShouldExist" is present')
client.Streams.stdout += Testers.ContainsExpression(
    'Presence Success: Key: "1", Field Name: "content-length", Value: "0"',
    'Validation should be happy that "content-length" is present.')
client.Streams.stdout += Testers.ContainsExpression(
    'Presence Success: Key: "1", Field Name: "age", Value: "4"',
    'Validation should be happy that "Age" is present even though its value differs.')
client.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. Key: "1", Field Name: "x-request-id"',
    'Validation should complain that "x-request-id" is misssing')
client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "date", Value: "Sat, 16 Mar 2019 03:11:36 GMT"',
    'Validation should be happy that "date" has the expected value.')
client.Streams.stdout += Testers.ContainsExpression(
    ('Equals Violation: Different. Key: "1", Field Name: "x-testheader", '
     'Correct Value: "from_proxy_response", Actual Value: "from_server_response"'),
    'Validation should complain that the "x-testheader" value differs from the expected value.')

client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 2: Verify field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client2", "replay_files/cookie_equal.yaml")
server = r.AddServerProcess("server2", "replay_files/cookie_equal.yaml")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    'Absence Success: Key: "5", Field Name: "x-not-a-header"',
    'Validation should be happy that "X-Not-A-Header" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
    'Validation should be happy that "Set-Cookie" had the expected header.')

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
    'Validation should be happy that "Set-Cookie" had the expected header.')

client.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. Key: "5", Field Name: "x-does-not-exist"',
    'Validation should complain that "X-Does-Not-Exist" is not present.')

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "5", Field Name: "x-test-request", Correct Value: "rEQUESTdATA", Actual Value: "RequestData"',
    'Validation should complain that "X-Test-Request" is different.')

server.Streams.stdout += Testers.ContainsExpression(
    'Absence Violation: Present. Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should complain that "X-Test-Pressent" is present.')

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "5", Field Name: "cookie", Value: "',
    'Validation should be happy with the cookie value.')

client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 3: Verify repeated RFC-combinable header fields are normalized for verification.
#
r = Test.AddTestRun("Verify repeated RFC-combinable header fields are normalized for verification")
client = r.AddClientProcess("client3", "replay_files/duplicate_fields.yaml")
server = r.AddServerProcess("server3", "replay_files/duplicate_fields.yaml")
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "cache-control", Value: "no-store, max-age=0"',
    'Validation should combine repeated Cache-Control field lines before comparing them.')

client.Streams.stdout += Testers.ContainsExpression(
    ('Equals Violation: Different. Key: "1", Field Name: "cache-control", '
     'Correct Value: "max-age=0, no-store", Actual Value: "no-store, max-age=0"'),
    'Validation should preserve the order of repeated Cache-Control values.')

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "vary", Value: "accept-encoding, accept-language"',
    'Validation should treat a single comma-separated Vary field line like repeated field lines.')

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "x-join", Value: "alpha, beta"',
    'Validation should join repeated request field lines with comma SP before equality checks.')

server.Streams.stdout += Testers.ContainsExpression(
    ('Equals Violation: Different. Key: "1", Field Name: "x-join", '
     'Correct Value: "beta, alpha", Actual Value: "alpha, beta"'),
    'Validation should fail when the repeated request field order changes.')

server.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "1", Field Name: "x-join", Required Value: "beta", Value: "alpha, beta"',
    'Validation should run substring checks against the combined request field value.')

client.ReturnCode = 1
server.ReturnCode = 1

# Test 4: Verify Set-Cookie verification uses the dedicated set-cookie-verifications node.
r = Test.AddTestRun(
    "Verify Set-Cookie verification works with the dedicated set-cookie-verifications node")
client = r.AddClientProcess("client4", "replay_files/multi_value_includes.yaml")
server = r.AddServerProcess("server4", "replay_files/multi_value_includes.yaml")
proxy = r.AddProxyProcess("proxy4", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "B1=333"',
    "Verification should match a Set-Cookie rule even when the replay lists it out of order.")

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "A1=111"',
    "Verification should match the remaining Set-Cookie rule after the first match is consumed.")

client.ReturnCode = 0
server.ReturnCode = 0

# Test 5: Verify Set-Cookie verification allows extra cookies after the expected list.
r = Test.AddTestRun("Verify Set-Cookie verification allows extra cookies after the expected list")
client = r.AddClientProcess("client5", "replay_files/multi_value_equal.yaml")
server = r.AddServerProcess("server5", "replay_files/multi_value_equal.yaml")
proxy = r.AddProxyProcess("proxy5", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1=", Value: "A1=111"',
    "Verification should match the first expected Set-Cookie rule.")

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "B1=333"',
    "Verification should match the second expected Set-Cookie rule and ignore later cookies.")

client.ReturnCode = 0
server.ReturnCode = 0

# Test 6: Verify Set-Cookie negative checks do not consume cookies and value arrays expand.
r = Test.AddTestRun("Verify negative Set-Cookie checks assert no matching cookie line")
client = r.AddClientProcess("client6", "replay_files/set_cookie_negative.yaml")
server = r.AddServerProcess("server6", "replay_files/set_cookie_negative.yaml")
proxy = r.AddProxyProcess("proxy6", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1=", Value: "A1=111"',
    "Verification should expand a Set-Cookie contains array into individual checks.")

client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1S=", Value: "A1S=555"',
    "Verification should match each expanded Set-Cookie contains rule independently.")

client.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Success: Absent. Key: "1", Field Name: "set-cookie", Required Missing Value: "D1="',
    "Verification should treat Set-Cookie absent-with-value as a negative non-consuming match.")

client.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Success: Absent. Key: "1", Field Name: "set-cookie", Required Missing Value: "_ebd"',
    "Verification should expand a Set-Cookie absent array into individual negative checks.")

client.ReturnCode = 0
server.ReturnCode = 0

# Test 7: Verify legacy Set-Cookie absence and negative pattern checks still work.
r = Test.AddTestRun("Verify Set-Cookie absence works in both legacy and dedicated syntax")
client = r.AddClientProcess("client7", "replay_files/set_cookie_absent.yaml")
server = r.AddServerProcess("server7", "replay_files/set_cookie_absent.yaml")
proxy = r.AddProxyProcess("proxy7", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Absence Success: Key: "1", Field Name: "set-cookie"',
    "Legacy Set-Cookie absence verification under fields should still work.")

client.ReturnCode = 0
server.ReturnCode = 0

# Test 8: Verify a negative Set-Cookie pattern check fails on a matching cookie line.
r = Test.AddTestRun("Verify a negative Set-Cookie pattern fails when a cookie matches")
client = r.AddClientProcess("client8", "replay_files/set_cookie_negative_failure.yaml")
server = r.AddServerProcess("server8", "replay_files/set_cookie_negative_failure.yaml")
proxy = r.AddProxyProcess("proxy8", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "A1=111"',
    "Verification should still match the positive Set-Cookie rule.")

client.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Violation: Key: "1", Field Name: "set-cookie", Required Missing Value: "B1=333", Value: "B1=333"',
    "Verification should fail when an absent Set-Cookie pattern matches a received cookie.")

client.ReturnCode = 1
server.ReturnCode = 0
