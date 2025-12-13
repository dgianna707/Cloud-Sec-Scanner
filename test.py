#import httpx
#import yaml
from scanner.models import Finding
print("(„• ֊ •„)੭ Python Enviornment is Ready! ᶻ 𝘇 𐰁 ")

f = Finding (
    id = "NO_HTTPS",
    severity = "CRITICAL",
    description = "Target URL is not using HTTPS.",
    evidence = "URL: http://example.com",
    remediation = "Serve the application over HTTPS.",

)
print(f)





