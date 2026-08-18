complete -c jirakeep -l jira-server -d 'Base URL of the Jira site (e.g. \'https://example.atlassian.net\' or a DC host)' -r
complete -c jirakeep -l auth-mode -d 'Authentication mode: \'basic\' (Cloud email+token, default) or \'bearer\' (DC PAT)' -r -f -a "basic\t'Cloud Basic auth: email + API token (default)'
bearer\t'Bearer token: Data Center personal access token (email not required)'"
complete -c jirakeep -l api-version -d 'Jira REST API version: \'2\' (Data Center) or \'3\' (Cloud). Defaults by auth mode: basic -> 3, bearer -> 2' -r -f -a "2\t'`/rest/api/2` — Jira Data Center'
3\t'`/rest/api/3` — Jira Cloud'"
complete -c jirakeep -l transport -d 'Transport for the MCP server: \'http\' (default) or \'stdio\'' -r -f -a "http\t'Streamable HTTP transport (default)'
stdio\t'Stdio transport'"
complete -c jirakeep -l host -d 'Host address for the MCP server to listen on (http transport only)' -r
complete -c jirakeep -l port -d 'Port for the MCP server to listen on (http transport only)' -r
complete -c jirakeep -l api-key-header -d 'HTTP header for clients to send the Jira API token' -r
complete -c jirakeep -l email-header -d 'HTTP header for clients to send the Atlassian account email (per-request Cloud Basic auth when --email is not set on the server)' -r
complete -c jirakeep -l api-key -d 'Jira Cloud API token' -r
complete -c jirakeep -l api-key-file -d 'Path to a file holding the Jira Cloud API token' -r -F
complete -c jirakeep -l email -d 'Atlassian account email for Cloud Basic auth' -r
complete -c jirakeep -l email-file -d 'Path to a file holding the Atlassian account email' -r -F
complete -c jirakeep -l policy -d 'Path to the guard policy TOML file' -r -F
complete -c jirakeep -l audit-config -d 'Path to the audit configuration TOML file' -r -F
complete -c jirakeep -l read-only -d 'Disables all tools which modify Jira state'
complete -c jirakeep -s h -l help -d 'Print help (see more with \'--help\')'
complete -c jirakeep -s V -l version -d 'Print version'
