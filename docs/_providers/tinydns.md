---
name: tinydns
title: tinydns Provider
layout: default
jsId: TINYDNS
---
# Tinydns Provider
This provider maintains a directory with a single data file.  This script does not call the tinydns-data functions to generate the necessary data.cdb file.  Transfer the data file and updating your data.cdb are exercises left to the reader.

More information on tinydns can be found at https://cr.yp.to/djbdns/tinydns.html .

## Configuration
In your credentials file (`creds.json`), you can specify a `directory` where the provider will look for and create the data file. The default is the `zones` directory where dnscontrol is run.

{% highlight json %}
{
  "tinydns": {
    "directory": "myzones"
  }
}
{% endhighlight %}

The tinydns provider does not require anything in `creds.json`. It does accept some optional metadata via your DNS config when you create the provider:

{% highlight javascript %}
var tiny = NewDnsProvider('tinydns', 'TINYDNS', {
    'default_soa': {
        'master': 'ns1.example.tld.',
        'mbox': 'sysadmin.example.tld.',
        'refresh': 3600,
        'retry': 600,
        'expire': 604800,
        'minttl': 1440,
    }
})
{% endhighlight %}

If you need to customize your SOA records, you can do so with this setup.
