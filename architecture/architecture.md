flowchart TD
    A[User (GUI / CLI)] --> B[Recon Engine - recon.py]
    B --> C[WHOIS Lookup Module]
    B --> D[Subdomain Enumeration Module]
    C --> E[Report Generation]
    D --> E
    E --> F[SQLite Database Logging]
