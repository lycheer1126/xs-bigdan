---
name: source-leak
description: >
  Source code leak detection via GitHub, Gitee, and search engine
  dorking. Uses tech stack fingerprints to construct targeted search
  queries for leaked source code, configs, and credentials.
metadata:
  tags: "source-leak,github,gitee,credentials,config"
  category: "offensive-security"
---

# Source Code Leak Search

## Methodology

```
Step 1: Tech fingerprint → determine search keywords
├── Frontend: Vue/React specific code snippets
├── Backend: /actuator, /api/xxx patterns
├── Page title/copyright/error message characteristic strings
└── Cookie names/Session ID format

Step 2: GitHub/Gitee search
├── site:github.com "unique string" (Google dork)
├── github_search_code with unique code snippets
├── gitee_search_open_source_repositories with product name
└── Priority: config files > source code > documentation

Step 3: Secondary confirmation
├── Compare directory structure
├── Compare API routes
├── Compare frontend JS variable names/comments
└── Save links after confirmation — do NOT download
```

## Search Query Construction

```
# From tech fingerprint → search queries:
1. Unique error messages:
   "com.example.controller" "Internal Server Error"

2. Cookie/Header patterns:
   "JSESSIONID" "companyname"

3. Frontend code snippets:
   "apiBaseUrl" "https://target.com"

4. Page titles:
   "XX管理系统" in:readme

5. File patterns:
   "application.yml" "spring.datasource.url"
   ".env" "DB_PASSWORD"

6. Framework config paths:
   path:pom.xml "groupId" "artifact"
   path:composer.json "name"
```

## High-Value Targets

```
□ Config files: application.yml, .env, settings.py, config.js
□ Database config: JDBC URL, DB credentials, connection strings
□ API keys: cloud service keys, third-party API keys
□ Internal docs: README with architecture, deployment guide
□ Test code: test data with real credentials
□ CI/CD config: .gitlab-ci.yml, Jenkinsfile, GitHub Actions
□ Docker config: Dockerfile, docker-compose.yml, environment vars
```

## Tools

```
github_search_code: unique code snippet from target's JS
github_search_repositories: product/company name
gitee_search_open_source_repositories: product name

Google dork:
site:github.com "target-unique-string"
site:gitee.com "target-unique-identifier"

GitDorker / truffleHog: for credential leaks
Focus: .env, config files, docker-compose.yml, credentials.json
```
