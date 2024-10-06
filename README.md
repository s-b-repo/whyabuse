This script works well for downloading and aggregating banned IP lists from multiple sources, saving them to a file, and allowing you to search for specific IPs

Explanation of api:

    API Key Prompts: Prompts the user for AlienVault and VirusTotal API keys. If provided, these keys will be used in lookups; if not, lookups are skipped.
    AlienVault and VirusTotal Lookup Functions: alien_vault_lookup() and virus_total_lookup() functions perform API requests to retrieve information on the specified IP. Each function checks if an API key is present before proceeding.
    User IP Search: Prompts the user for an IP to search, then performs a search through banned_ips and makes lookups via AlienVault and VirusTotal if API keys are available.
