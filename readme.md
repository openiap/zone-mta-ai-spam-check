# zone-mta-ai-spam-check
Use OpenAI to scan new, or all email based on custom LLM prompts, per user or per domain,
before delivering the email to your real mail servers.

Copy config folder from zone-mta folder into the root folder
Edit default.js, 
- find `dbs` section and edit settings to use openiap's reddis and mongodb settings
make sure `sender` matches your openiap database ( default openflow )
- find `plugins` section and in the top add
```
        'user/ai-spam-check': {
            enabled: true,
            OPENAI_API_KEY: '',
            model: "gpt-3.5-turbo-1106",
            sendingZone: 'default',
        },
```
- find `default` under `zones`
change host to the lowest priority mx record in your dns. ( for instance if using google workspace, this should be `aspmx.l.google.com` )
If you are using different email providers for different domains, setup multiple zones for each domain and set `host` to match that mail provider
- optional: find `zones` and add this under the default zone.
```
        quarantine: {
            disabled: true
        },
```
this is only needed if you want to use both [zmta-webadmin](https://github.com/zone-eu/zmta-webadmin) and [zone-mta-web](https://github.com/openiap/zone-mta-web). If only using [zone-mta-web](https://github.com/openiap/zone-mta-web) this is not needed.

- pack and publish as a package in openiap
- create a new agent and forward port 25 into this agent
- deploy [zone-mta-web](https://github.com/openiap/zone-mta-web) to this are a seperate agent, and under config setup your settings.
It's **very** important you add all your incomming domains under `domains` with type `relay`. This is how you tell the plugin/zone-mta what domains to allow relaying for. Without this all mail will be rejected.
- Now edit dns for the/all the domains you added as relay and add a priority 1 record pointing to the public ip/domain used to access the agent on port 25.
if you already have a priority 1 record, change this to a higher priority ( this will be the record you need to use in the defaut zone mentioned above )

- if you cannot get a static IP with a good reputation or simply cannot get a static IP, then in google you can setup SMTP relay using [Routing](https://support.google.com/a/answer/2956491?hl=en), then select "Any addresses" and "Require SMTP Authentication". If you are using 2 factor authentication ( you SHOULD! ) then use [this guide](https://support.google.com/mail/answer/185833?hl=en) for setup app password, to use for authentication