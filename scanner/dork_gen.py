def generate_dorks(target):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    return [
        f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls',
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{domain} "index of" OR "directory listing"',
        f'site:{domain} ext:sql OR ext:db OR ext:backup OR ext:bak',
        f'site:{domain} "wp-config" OR "config.php" OR ".env"',
        f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2',
        f'site:{domain} "error" OR "exception" OR "stack trace"',
        f'site:{domain} filetype:log OR filetype:txt inurl:log',
    ]
