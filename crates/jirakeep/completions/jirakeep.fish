complete -c jirakeep -l jira-server -d 'Base URL of the Jira Cloud site (e.g. \'https://example.atlassian.net\'). Environment variable JIRA_SERVER is used if the argument is not provided' -r
complete -c jirakeep -l transport -d 'Transport for the MCP server: \'http\' (default) or \'stdio\'. Environment variable MCP_TRANSPORT can also be used' -r -f -a "http\t'Streamable HTTP transport (default). Clients send the Jira API token per-request via the API key header, unless `--api-key-file` selects server-held token mode (then the header is not consulted at all)'
stdio\t'Stdio transport. Token and email come from flags/env/files at startup'"
complete -c jirakeep -l host -d 'Host address for the MCP server to listen on (http transport only). Defaults to 127.0.0.1 or the MCP_HOST environment variable' -r
complete -c jirakeep -l port -d 'Port for the MCP server to listen on (http transport only). Defaults to 8000 or the MCP_PORT environment variable' -r
complete -c jirakeep -l api-key-header -d 'HTTP header for clients to send the Jira API token. Defaults to \'ApiKey\' or the MCP_API_KEY_HEADER environment variable. Not consulted in server-held token mode (--api-key-file over http)' -r
complete -c jirakeep -l api-key -d 'Jira Cloud API token. Required for --transport stdio unless --api-key-file provides it. Environment variable JIRA_API_TOKEN can also be used. Ignored for --transport http unless --api-key-file is set (clients send the token per-request; use --api-key-file for a server-held token)' -r
complete -c jirakeep -l api-key-file -d 'Path to a file holding the Jira Cloud API token. Mutually exclusive with --api-key. Over http this selects server-held token mode' -r -F
complete -c jirakeep -l email -d 'Atlassian account email for Cloud Basic auth. Environment variable JIRA_EMAIL can also be used. Required whenever a token is used (stdio, or http server-held mode)' -r
complete -c jirakeep -l email-file -d 'Path to a file holding the Atlassian account email. Mutually exclusive with --email' -r -F
complete -c jirakeep -l policy -d 'Path to the guard policy TOML file. Environment variable JIRAKEEP_POLICY can also be used. Without it an allow-all default policy is used (restricted comments still off)' -r -F
complete -c jirakeep -l read-only -d 'Disables all tools which modify Jira state. Environment variable MCP_READ_ONLY=true can also be used. Can only tighten the guard policy, never loosen it'
complete -c jirakeep -s h -l help -d 'Print help (see more with \'--help\')'
complete -c jirakeep -s V -l version -d 'Print version'
