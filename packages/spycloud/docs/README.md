# SpyCloud Enterprise Protection

## Ingest SpyCloud Cybercrime Analytics into Elastic Agent

[SpyCloud’s Enterprise Protection](https://spycloud.com/) integration leverages recaptured darknet data to safeguard employees' digital identities by producing actionable insights to proactively prevent account takeover and follow-on targeted attacks before they happen.

The Elastic Agent uses the SpyCloud Enterprise Protection REST API to collect data.

## Compatibility

This module has been tested against the latest SpyCloud Enterprise Protection API **V2**.

## Data streams

The SpyCloud integration collects three types of logs: Breach Catalog, Breach Record and Compass Malware Records.

**[Breach Catalog](https://spycloud-external.readme.io/sc-enterprise-api/reference/catalog-list)** - a collection of third-party breach and malware data ingested into SpyCloud. The catalog contains thousands of breach objects, each of which contain metadata for a particular breach. A typical breach object contains a variety of metadata including a breach title, description, acquisition date, link to affected websites and many more data points.

**[Breach Record](https://spycloud-external.readme.io/sc-enterprise-api/reference/data-watchlist)** - a collection of data assets extracted from third-party breach and malware data. These assets are grouped together to form a data record which represents a single user account or individual persona in parsed data.

**[Compass Malware Records](https://spycloud-external.readme.io/sc-enterprise-api/reference/compass-data-get)** - a collection of data assets extracted from malware data that provides full visibility into infection events to enable post-infection remediation on compromised devices, users, and applications.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

- Considering you already have a SpyCloud account, log in to your SpyCloud instance to obtain your API key. Navigate to **Main > API**, where you will find your API key under the **Keys > API Key** section.
- To obtain the Base URL, navigate to **Main > API** and click on the **View Docs** link, your URL can be located within the **API Reference** section.

**NOTE**: Your system's IP should be allowlisted by the SpyCloud team to be able to access the APIs and get the data.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type SpyCloud Enterprise Protection.
3. Click on the "SpyCloud Enterprise Protection" integration from the search results.
4. Click on the Add SpyCloud Enterprise Protection Integration button to add the integration.
5. While adding the integration, if you want to collect Breach Catalog logs via REST API, please enter the following details:
   - URL
   - API Key
   - Interval

   or if you want to collect Breach Record logs via REST API, please enter the following details:
   - URL
   - API Key
   - Initial Interval
   - Interval
   - Severity

   or if you want to collect Compass logs via REST API, please enter the following details:
   - URL
   - API Key
   - Initial Interval
   - Interval

**NOTE**: By default, the URL is set to "https://api.spycloud.io/enterprise-v2".

## Logs Reference

### Breach Catalog

This is the `Breach Catalog` dataset.

#### Example

An example event for `breach_catalog` looks as following:

```json
{
    "@timestamp": "2022-11-24T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "d6e9d6f0-0baa-44b6-b60b-e4b811e50811",
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spycloud.breach_catalog",
        "namespace": "63685",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spycloud.breach_catalog",
        "id": "39997",
        "ingested": "2024-08-16T06:23:24Z",
        "kind": "asset",
        "original": "{\"acquisition_date\":\"2022-10-14T00:00:00Z\",\"assets\":{\"address_2\":363,\"age\":817,\"city\":1859,\"country\":177225,\"country_code\":177225,\"dob\":198,\"email\":177219,\"first_name\":177114,\"full_name\":177030,\"gender\":119505,\"industry\":162612,\"job_title\":160712,\"last_name\":177099,\"middle_name\":17749,\"phone\":511,\"postal_code\":1971,\"social_facebook\":51841,\"social_twitter\":57193},\"confidence\":3,\"description\":\"This source has been marked as sensitive due to one of the following reasons: Revealing the source may compromise an on-going investigation. The affected site is of a controversial nature but does not validate email addresses and could therefore be used to tarnish an employee's reputation.\",\"id\":39997,\"num_records\":177225,\"spycloud_publish_date\":\"2022-11-24T00:00:00Z\",\"title\":\"Sensitive Source\",\"type\":\"PRIVATE\",\"uuid\":\"9f5bf34b-092e-46f4-b87f-02c91b0adb3a\"}"
    },
    "input": {
        "type": "cel"
    },
    "message": "This source has been marked as sensitive due to one of the following reasons: Revealing the source may compromise an on-going investigation. The affected site is of a controversial nature but does not validate email addresses and could therefore be used to tarnish an employee's reputation.",
    "spycloud": {
        "breach_catalog": {
            "acquisition_date": "2022-10-14T00:00:00.000Z",
            "assets": {
                "address": {
                    "value_2": 363
                },
                "age": 817,
                "city": 1859,
                "country": {
                    "code": 177225,
                    "name": 177225
                },
                "dob": 198,
                "email": {
                    "value": 177219
                },
                "first_name": 177114,
                "full_name": 177030,
                "gender": 119505,
                "industry": 162612,
                "job": {
                    "title": 160712
                },
                "last_name": 177099,
                "middle_name": 17749,
                "phone": 511,
                "postal_code": 1971,
                "social": {
                    "facebook": 51841,
                    "twitter": 57193
                }
            },
            "confidence": 3,
            "description": "This source has been marked as sensitive due to one of the following reasons: Revealing the source may compromise an on-going investigation. The affected site is of a controversial nature but does not validate email addresses and could therefore be used to tarnish an employee's reputation.",
            "id": "39997",
            "num_records": 177225,
            "spycloud_publish_date": "2022-11-24T00:00:00.000Z",
            "title": "Sensitive Source",
            "type": "PRIVATE",
            "uuid": "9f5bf34b-092e-46f4-b87f-02c91b0adb3a"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "spycloud-breach_catalog"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| spycloud.breach_catalog.acquisition_date | The date on which our security research team first acquired the breached data. | date |
| spycloud.breach_catalog.assets.account.caption | Account profile caption. | long |
| spycloud.breach_catalog.assets.account.image_url | Account image URL. | long |
| spycloud.breach_catalog.assets.account.last_activity_time | Timestamp of last account activity. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.account.login_time | Last account login time. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.account.modification_time | Account modification date. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.account.nickname | Account nickname. | long |
| spycloud.breach_catalog.assets.account.notes | Account notes. | long |
| spycloud.breach_catalog.assets.account.password_date | Date on which the account password was set. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.account.secret.answer | Account secret answer. | long |
| spycloud.breach_catalog.assets.account.secret.question | Account secret question. | long |
| spycloud.breach_catalog.assets.account.signup_time | Account signup date. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.account.status | Account status. | long |
| spycloud.breach_catalog.assets.account.title | Account title. | long |
| spycloud.breach_catalog.assets.account.type | Account type. | long |
| spycloud.breach_catalog.assets.active_investor | Set to 'y' if this person is classified as an active investor, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.address.value_1 | Address line 1. | long |
| spycloud.breach_catalog.assets.address.value_2 | Address line 2. | long |
| spycloud.breach_catalog.assets.age | Age (in years). | long |
| spycloud.breach_catalog.assets.av_softwares | List of AV software found installed on the infected user's system. | long |
| spycloud.breach_catalog.assets.backup.email.username | Backup username extracted from 'backup_email' field. This is everything before the '@' symbol. | long |
| spycloud.breach_catalog.assets.backup.email.value | Backup email address. | long |
| spycloud.breach_catalog.assets.bank_number | Bank account number. | long |
| spycloud.breach_catalog.assets.birthplace | Birth location of this person. | long |
| spycloud.breach_catalog.assets.buys_online | Set to 'y' if this person is classified as having purchased products online, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.cat_owner | Set to 'y' if this person is classified as a cat owner, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.cc.bin | Credit card bin number. | long |
| spycloud.breach_catalog.assets.cc.code | Credit card security code. | long |
| spycloud.breach_catalog.assets.cc.expiration | Credit card expiration date. Typically in MM/YYYY format. | long |
| spycloud.breach_catalog.assets.cc.last_four | Last four digits of credit card. | long |
| spycloud.breach_catalog.assets.cc.number | SHA1 hash of credit card number. | long |
| spycloud.breach_catalog.assets.cc.type | Credit card type (VISA, MasterCard, Discover, AMEX, etc). | long |
| spycloud.breach_catalog.assets.christian_family | Set to 'y' if this person is classified being part of a Christian family, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.city | City name. | long |
| spycloud.breach_catalog.assets.company.name | Company name. | long |
| spycloud.breach_catalog.assets.company.revenue | Company revenue. | long |
| spycloud.breach_catalog.assets.company.website | URL of company associated with this person. | long |
| spycloud.breach_catalog.assets.country.code | Country code; derived from Country. | long |
| spycloud.breach_catalog.assets.country.name | Country name. | long |
| spycloud.breach_catalog.assets.credit_rating | Credit rating for this person. | long |
| spycloud.breach_catalog.assets.crm.contact_created | Timestamp when this contact was first created in a CRM platform. | long |
| spycloud.breach_catalog.assets.crm.last_activity | Timestamp of last activity for this account from a CRM platform. | long |
| spycloud.breach_catalog.assets.date_of_death | Date of death of this person. | long |
| spycloud.breach_catalog.assets.desc | Description. | long |
| spycloud.breach_catalog.assets.device.model | Model of this person's device. | long |
| spycloud.breach_catalog.assets.device.name | Name of this person's device. | long |
| spycloud.breach_catalog.assets.display_resolution | The system display resolution. | long |
| spycloud.breach_catalog.assets.dob | Date of birth. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.document_id | UUID v4 string which uniquely identifies this breach record in our data set. | long |
| spycloud.breach_catalog.assets.dog_owner | Set to 'y' if this person is classified as a dog owner, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.domain | Domain name. | long |
| spycloud.breach_catalog.assets.drivers.license.number | Driver's license number. | long |
| spycloud.breach_catalog.assets.drivers.license.state_code | State code of driver's license; derived from drivers_license if pended. | long |
| spycloud.breach_catalog.assets.ec.first_name | First name of emergency contact. | long |
| spycloud.breach_catalog.assets.ec.last_name | Last name of emergency contact. | long |
| spycloud.breach_catalog.assets.ec.phone | Phone number of emergency contact. | long |
| spycloud.breach_catalog.assets.ec.postal_code | Postal code of emergency contact. | long |
| spycloud.breach_catalog.assets.ec.relation | Relationship with emergency contact. | long |
| spycloud.breach_catalog.assets.education | Level of education completed. | long |
| spycloud.breach_catalog.assets.email.domain | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | long |
| spycloud.breach_catalog.assets.email.status | Email status. Denotes whether an email has been verified or not in a CRM platform. | long |
| spycloud.breach_catalog.assets.email.username | Username extracted from 'email' field. This is everything before the '@' symbol. | long |
| spycloud.breach_catalog.assets.email.value | Email address. | long |
| spycloud.breach_catalog.assets.employees | Number of employees of company associated with this person. | long |
| spycloud.breach_catalog.assets.estimated_income | Estimated income range. | long |
| spycloud.breach_catalog.assets.ethnic_group | Ethnic group associated with this person. | long |
| spycloud.breach_catalog.assets.ethnicity | Ethnicity of this person. | long |
| spycloud.breach_catalog.assets.fax | Fax number. | long |
| spycloud.breach_catalog.assets.first_name | First name. | long |
| spycloud.breach_catalog.assets.form.cookies_data | Cookie data associated with this person. | long |
| spycloud.breach_catalog.assets.form.post_data | Form post data associated with this person. | long |
| spycloud.breach_catalog.assets.full_name | Full name. | long |
| spycloud.breach_catalog.assets.gender | Gender specifier. Typically set to 'M', 'F', 'Male', or 'Female'. | long |
| spycloud.breach_catalog.assets.geolocation | Geolocation coordinates. Stored as 'latitude,longitude'. | long |
| spycloud.breach_catalog.assets.grandchildren | Set to 'y' if this person is classified as having grandchildren, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.guid | Globally unique identifier. | long |
| spycloud.breach_catalog.assets.has.air_conditioning | Type of air conditioning. | long |
| spycloud.breach_catalog.assets.has.amex_card | Set to 'y' if this person is classified as having an American Express credit card, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.children | Set to 'y' if this person is classified as having children, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.credit_cards | Set to 'y' if this person has a credit card, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.discover_card | Set to 'y' if this person is classified as having a Discover credit card, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.mastercard | Set to 'y' if this person is classified as having a MasterCard credit card, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.pets | Set to 'y' if this person is classified as having pets, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.swimming_pool | Set to 'y' if this person is classified as having a swimming pool, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.has.visa_card | Set to 'y' if this person is classified as having a VISA credit card, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.health.insurance.id | SHA1 hash of the health insurance ID. | long |
| spycloud.breach_catalog.assets.health.insurance.provider | Health insurance provider. | long |
| spycloud.breach_catalog.assets.hobbies_and_interests | List of hobbies and interests associated with this person. | long |
| spycloud.breach_catalog.assets.home.build_year | Home build year. | long |
| spycloud.breach_catalog.assets.home.purchase.date | Home purchase date. | long |
| spycloud.breach_catalog.assets.home.purchase.price | Home purchase price. | long |
| spycloud.breach_catalog.assets.home.transaction_type | Home transaction type. | long |
| spycloud.breach_catalog.assets.home.value | Current estimated home value. | long |
| spycloud.breach_catalog.assets.homepage | User's homepage URL. | long |
| spycloud.breach_catalog.assets.industry | Industry in which this person works. | long |
| spycloud.breach_catalog.assets.infected.machine_id | The unique id of the infected user's system. | long |
| spycloud.breach_catalog.assets.infected.path | The local path to the malicious software installed on the infected user's system. | long |
| spycloud.breach_catalog.assets.infected.time | The time at which the user's system was infected with malicious software. | long |
| spycloud.breach_catalog.assets.investments.personal | Set to 'y' if this person is classified as having made personal investments, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.investments.real_estate | Set to 'y' if this person is classified as having made real estate investments, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.ip_addresses | List of one or more IP addresses in alphanumeric format. Both IPv4 and IPv6 addresses are supported. | long |
| spycloud.breach_catalog.assets.is_smoker | Set to 'y' if this person is classified as a smoker, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.isp | Name of internet service provider. | long |
| spycloud.breach_catalog.assets.job.level | Job level. | long |
| spycloud.breach_catalog.assets.job.start_date | Job start date. | long |
| spycloud.breach_catalog.assets.job.title | Job title. | long |
| spycloud.breach_catalog.assets.keyboard_languages | Represents the keyboard languages associated with the compromised account. | long |
| spycloud.breach_catalog.assets.language | Account language preferences. | long |
| spycloud.breach_catalog.assets.last_name | Last name. | long |
| spycloud.breach_catalog.assets.linkedin_number_connections | Number of LinkedIn connections for this person. | long |
| spycloud.breach_catalog.assets.log_id |  | long |
| spycloud.breach_catalog.assets.logon_server | Logon server. | long |
| spycloud.breach_catalog.assets.marital_status | Marital status of this person. | long |
| spycloud.breach_catalog.assets.middle_name | Middle name. | long |
| spycloud.breach_catalog.assets.mortgage.amount | Mortgage amount. | long |
| spycloud.breach_catalog.assets.mortgage.lender_name | Mortgage lender name. | long |
| spycloud.breach_catalog.assets.mortgage.loan_type | Mortgage loan type. | long |
| spycloud.breach_catalog.assets.mortgage.rate | Mortgage rate. | long |
| spycloud.breach_catalog.assets.naics_code | North American Industry Classification System code. | long |
| spycloud.breach_catalog.assets.name_suffix | Name suffix. | long |
| spycloud.breach_catalog.assets.national_id | National Indentification number. | long |
| spycloud.breach_catalog.assets.net_worth | Networth of this person. | long |
| spycloud.breach_catalog.assets.num_posts | Number of posts of an account (typically associated with a forum). | long |
| spycloud.breach_catalog.assets.number_children | Number of children. | long |
| spycloud.breach_catalog.assets.passport.country | Passport country. | long |
| spycloud.breach_catalog.assets.passport.exp_date | Passport expiration date. | long |
| spycloud.breach_catalog.assets.passport.issue_date | Passport issue date. | long |
| spycloud.breach_catalog.assets.passport.number | Passport number. | long |
| spycloud.breach_catalog.assets.password.plaintext | The cracked, plaintext version of the password (where the password is crackable). | long |
| spycloud.breach_catalog.assets.password.type | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types (SHA1, MD5, 3DES, etc). | long |
| spycloud.breach_catalog.assets.password.value | Account password. | long |
| spycloud.breach_catalog.assets.pastebin_key | The pastebin from where this credential was recovered from. | long |
| spycloud.breach_catalog.assets.payableto | Payable to name. | long |
| spycloud.breach_catalog.assets.phone | Phone number. | long |
| spycloud.breach_catalog.assets.political_affiliation | Political affiliation of this person. 'R' for Republican, 'D' for Democrat, 'I' for Independent, 'O' for other. | long |
| spycloud.breach_catalog.assets.postal_code | Postal code, usually zip code in USA. | long |
| spycloud.breach_catalog.assets.record.addition_date | Included if a record has been added since its original spycloud_publish_date. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.record.cracked_date | Included if a record’s hashed password has been successfully cracked after it was originally published. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.record.modification_date | Included if a record has been updated since its original spycloud_publish_date. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.religion | Religion associated to this person. | long |
| spycloud.breach_catalog.assets.residence_length_years | Number of years at current residence. This value tops out at 15, so 15 may indiciate 15 years or more. | long |
| spycloud.breach_catalog.assets.salt | Password salt. | long |
| spycloud.breach_catalog.assets.service.expiration | The expiration date of the associated service. In ISO 8601 datetime format. | long |
| spycloud.breach_catalog.assets.service.value | The service this credential pair is associated with. i.e. (Spotify, Netflix, Steam, etc.). | long |
| spycloud.breach_catalog.assets.severity | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. | long |
| spycloud.breach_catalog.assets.sewer_type | Sewer type. | long |
| spycloud.breach_catalog.assets.sic_code | Standard Industrical Classification. | long |
| spycloud.breach_catalog.assets.single_parent | Set to 'y' if this person is classified as a single parent, otherwise set to 'n'. | long |
| spycloud.breach_catalog.assets.social.aboutme | AboutMe username. | long |
| spycloud.breach_catalog.assets.social.aim | AIM username. | long |
| spycloud.breach_catalog.assets.social.angellist | AngelList username. | long |
| spycloud.breach_catalog.assets.social.behance | BeHance username. | long |
| spycloud.breach_catalog.assets.social.crunchbase | Crunchbase username. | long |
| spycloud.breach_catalog.assets.social.dribble | Dribble username. | long |
| spycloud.breach_catalog.assets.social.facebook | Facebook username. | long |
| spycloud.breach_catalog.assets.social.flickr | Flickr username. | long |
| spycloud.breach_catalog.assets.social.foursquare | FourSquare username. | long |
| spycloud.breach_catalog.assets.social.github | GitHub username. | long |
| spycloud.breach_catalog.assets.social.gitlab | GitLab username. | long |
| spycloud.breach_catalog.assets.social.google | Google username. | long |
| spycloud.breach_catalog.assets.social.gravatar | Gravatar username. | long |
| spycloud.breach_catalog.assets.social.icq | ICQ username. | long |
| spycloud.breach_catalog.assets.social.indeed | Indeed username. | long |
| spycloud.breach_catalog.assets.social.instagram | Instagram username. | long |
| spycloud.breach_catalog.assets.social.klout | Klout username. | long |
| spycloud.breach_catalog.assets.social.linkedin | LinkedIn username or URL. | long |
| spycloud.breach_catalog.assets.social.medium | Medium username. | long |
| spycloud.breach_catalog.assets.social.meetup | Meetup username. | long |
| spycloud.breach_catalog.assets.social.msn | MSN username. | long |
| spycloud.breach_catalog.assets.social.myspace | Myspace username. | long |
| spycloud.breach_catalog.assets.social.other | Other social media usernames. | long |
| spycloud.breach_catalog.assets.social.pinterest | Pinterest username. | long |
| spycloud.breach_catalog.assets.social.quora | Quora username. | long |
| spycloud.breach_catalog.assets.social.reddit | Reddit username. | long |
| spycloud.breach_catalog.assets.social.security_number | SHA1 hash of the social security number. | long |
| spycloud.breach_catalog.assets.social.skype | Skype username. | long |
| spycloud.breach_catalog.assets.social.soundcloud | SoundCloud username. | long |
| spycloud.breach_catalog.assets.social.stackoverflow | StackOverflow username. | long |
| spycloud.breach_catalog.assets.social.steam | Steam username. | long |
| spycloud.breach_catalog.assets.social.telegram | Telegram username. | long |
| spycloud.breach_catalog.assets.social.twitter | Twitter username. | long |
| spycloud.breach_catalog.assets.social.vimeo | Vimeo username. | long |
| spycloud.breach_catalog.assets.social.weibo | Weibo username. | long |
| spycloud.breach_catalog.assets.social.whatsapp | WhatsApp username. | long |
| spycloud.breach_catalog.assets.social.wordpress | WordPress username. | long |
| spycloud.breach_catalog.assets.social.xing | Xing username. | long |
| spycloud.breach_catalog.assets.social.yahoo | Yahoo username. | long |
| spycloud.breach_catalog.assets.social.youtube | YouTube username or URL. | long |
| spycloud.breach_catalog.assets.source.file | Path / filename of source file (typically found in combolists). | long |
| spycloud.breach_catalog.assets.source.id | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | long |
| spycloud.breach_catalog.assets.spycloud_publish_date | The date on which this record was ingested into our systems. In ISO 8601 datetime format. This correlates with spycloud_publish_date field in Breach Catalog objects. | long |
| spycloud.breach_catalog.assets.ssn_last_four | The last four digits of the social security number. | long |
| spycloud.breach_catalog.assets.state | State name. | long |
| spycloud.breach_catalog.assets.system.install_date | Time at which system was installed. | long |
| spycloud.breach_catalog.assets.system.model | Model of system. | long |
| spycloud.breach_catalog.assets.target.domain | SLD extracted from 'target_url' field. | long |
| spycloud.breach_catalog.assets.target.subdomain | Subdomain and SLD extracted from 'target_url' field. | long |
| spycloud.breach_catalog.assets.target.url | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | long |
| spycloud.breach_catalog.assets.taxid | Tax identification ID. | long |
| spycloud.breach_catalog.assets.timezone | Timezone or timezone offset. | long |
| spycloud.breach_catalog.assets.title | Title of this person. | long |
| spycloud.breach_catalog.assets.user.agent | Browser agent string. | long |
| spycloud.breach_catalog.assets.user.browser | Browser name. | long |
| spycloud.breach_catalog.assets.user.hostname | System hostname. This usually comes from Botnet data. | long |
| spycloud.breach_catalog.assets.user.name | Username. | long |
| spycloud.breach_catalog.assets.user.os | System OS name. This usually comes from Botnet data. | long |
| spycloud.breach_catalog.assets.user.sys.domain | System domain. This usually comes from Botnet data. | long |
| spycloud.breach_catalog.assets.user.sys.registered.organization | System registered organization. This usually comes from Botnet data. | long |
| spycloud.breach_catalog.assets.user.sys.registered.owner | System registered owner name. This usually comes from Botnet data. | long |
| spycloud.breach_catalog.assets.vehicle.identification_number | Vehicle Identification Number. | long |
| spycloud.breach_catalog.assets.vehicle.make | Vehicle make. | long |
| spycloud.breach_catalog.assets.vehicle.model | Vehicle model. | long |
| spycloud.breach_catalog.assets.voter.id | Voter ID. | long |
| spycloud.breach_catalog.assets.voter.registration_date | Voter registration date. | long |
| spycloud.breach_catalog.assets.water_type | Water type. | long |
| spycloud.breach_catalog.breached_companies.company_name | Specifies the name of the company that experienced the breach. | keyword |
| spycloud.breach_catalog.breached_companies.industry | Specifies the industry that experienced the breach. | keyword |
| spycloud.breach_catalog.category | Specifies the specific category within the main breach category, providing additional details about the nature of the breach. | keyword |
| spycloud.breach_catalog.combo_list_flag | Indicates if the breach is a combo list. | boolean |
| spycloud.breach_catalog.confidence | Numerical score representing the confidence in the source of the breach. | long |
| spycloud.breach_catalog.consumer_category | Describes the consumer category associated with the breach, indicating the type of individuals or entities affected. | keyword |
| spycloud.breach_catalog.date | The date on which we believe the breach took place. | date |
| spycloud.breach_catalog.description | Breach description. For each ingested breach our security research team documents a breach description. This is only available when we can disclose the breach details, otherwise it will have a generic description. | keyword |
| spycloud.breach_catalog.id | Numerical breach ID. This number correlates to source_id data point found in breach records. | keyword |
| spycloud.breach_catalog.main_category | Indicates the main category to which the breach belongs. | keyword |
| spycloud.breach_catalog.media_urls | Array field. List of one or more media URLs referencing the breach in media. | keyword |
| spycloud.breach_catalog.num_records | Number of records we parsed and ingested from this particular breach. This is after parsing, normalization and deduplication take place. | long |
| spycloud.breach_catalog.premium_flag | Premium Flag. | boolean |
| spycloud.breach_catalog.public_date | The date on which this breach was made known to the public. This is usually accompanied by media URLs in media_urls list below. | date |
| spycloud.breach_catalog.sensitive_source | A boolean value indicating whether the source is considered sensitive. | boolean |
| spycloud.breach_catalog.short_title | A brief title or identifier associated with the breach. | keyword |
| spycloud.breach_catalog.site.description | Description of the breached organization, when available. | keyword |
| spycloud.breach_catalog.site.value | Website of breached organization, when available. | keyword |
| spycloud.breach_catalog.spycloud_publish_date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | date |
| spycloud.breach_catalog.title | Breach title. For each ingested breach our security research team documents a breach title. This is only available when we can disclose the breach details, otherwise it will have a generic title. | keyword |
| spycloud.breach_catalog.tlp | Stands for Traffic Light Protocol, which is a set of designations used to ensure the sharing of sensitive information is controlled. It can be "clear" or other levels. | keyword |
| spycloud.breach_catalog.type | Denotes if a breach is considered public or private. A public breach is one that is easily found on the internet, while a private breach is often exclusive to SpyCloud. | keyword |
| spycloud.breach_catalog.uuid | UUID v4 encoded version of breach ID. This is relevant for users of Firehose, where each deliverable (records file) is named using the breach UUID. | keyword |
| tags | User defined tags. | keyword |


### Breach Record

This is the `Breach Record` dataset.

#### Example

An example event for `breach_record` looks as following:

```json
{
    "@timestamp": "2023-11-29T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "ce02cb91-e24e-45fa-8591-70b683f1b86b",
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spycloud.breach_record",
        "namespace": "33260",
        "type": "logs"
    },
    "destination": {
        "domain": "example.com",
        "subdomain": "login.example.com"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spycloud.breach_record",
        "id": "3350f1da-fa39-4415-b2cc-02057e2fbe99",
        "ingested": "2024-08-16T06:24:19Z",
        "kind": "alert",
        "original": "{\"account_image_url\":\"https://www.chess.com/bundles/web/images/noavatar_l.84a92436.gif\",\"account_login_time\":\"2018-06-29T23:51:46Z\",\"account_modification_time\":\"2018-06-29T23:51:10Z\",\"account_signup_time\":\"2016-07-29T18:47:11Z\",\"av_softwares\":[\"McAfee\",\"Windows Defender\"],\"cc_bin\":\"489486\",\"cc_expiration\":\"06/2025\",\"cc_last_four\":\"1237\",\"cc_number\":\"3fdd0ce028ffaa147afdb6461f6ce95f8c07f484\",\"company_name\":\"ABC Corporation\",\"country\":\"United States\",\"country_code\":\"US\",\"display_resolution\":\"1920x1080\",\"document_id\":\"3350f1da-fa39-4415-b2cc-02057e2fbe99\",\"domain\":\"example1.com\",\"email\":\"john.doe@example.com\",\"email_domain\":\"example.com\",\"email_username\":\"john.doe\",\"first_name\":\"John\",\"full_name\":\"John Doe\",\"homepage\":\"https://www.chess.com/member/sarahjoh\",\"industry\":\"Technology\",\"infected_machine_id\":\"ABC123\",\"infected_path\":\"/documents/confidential\",\"infected_time\":\"2023-01-15T12:30:45Z\",\"ip_addresses\":[\"89.160.20.128\",\"89.160.20.112\"],\"job_title\":\"Software Engineer\",\"keyboard_languages\":[\"English\",\"Spanish\"],\"last_name\":\"Doe\",\"log_id\":\"76afa48107ec32f51a2aba4a314357c1e69d2267f1b04bf1afc948d0f77b1658\",\"password\":\"P@ssw0rd123\",\"password_plaintext\":\"******\",\"password_type\":\"alphanumeric\",\"record_addition_date\":\"2023-12-06T00:00:00Z\",\"record_cracked_date\":\"2023-11-29T00:00:00Z\",\"record_modification_date\":\"2023-11-29T00:00:00Z\",\"salt\":\"fbbdhd\",\"severity\":3,\"sighting\":17,\"social_linkedin\":[\"ildar-bazanov-961b14160\"],\"source_id\":50436,\"spycloud_publish_date\":\"2023-01-20T08:00:00Z\",\"target_domain\":\"example.com\",\"target_subdomain\":\"login.example.com\",\"target_url\":\"https://example.com/login\",\"user_browser\":\"Chrome\",\"user_hostname\":\"workstation-1\",\"user_os\":\"Windows 10\",\"user_sys_domain\":\"8ad8.default\",\"user_sys_registered_owner\":\"John Milk\",\"username\":\"john_doe\"}",
        "severity": 3
    },
    "host": {
        "geo": {
            "country_iso_code": "US",
            "country_name": "United States"
        },
        "hostname": "workstation-1",
        "ip": [
            "89.160.20.128",
            "89.160.20.112"
        ],
        "os": {
            "full": "Windows 10",
            "type": "windows"
        }
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "name": "ABC Corporation"
    },
    "related": {
        "hosts": [
            "workstation-1",
            "Windows 10",
            "8ad8.default"
        ],
        "ip": [
            "89.160.20.128",
            "89.160.20.112"
        ],
        "user": [
            "example1.com",
            "example.com",
            "john.doe",
            "John Doe",
            "john_doe",
            "John Milk"
        ]
    },
    "spycloud": {
        "breach_record": {
            "account": {
                "image_url": "https://www.chess.com/bundles/web/images/noavatar_l.84a92436.gif",
                "login_time": "2018-06-29T23:51:46.000Z",
                "modification_time": "2018-06-29T23:51:10.000Z",
                "signup_time": "2016-07-29T18:47:11.000Z"
            },
            "av_softwares": [
                "McAfee",
                "Windows Defender"
            ],
            "cc": {
                "bin": "REDACTED",
                "expiration": "REDACTED",
                "last_four": "REDACTED",
                "number": "REDACTED"
            },
            "company_name": "ABC Corporation",
            "country": {
                "code": "US",
                "name": "United States"
            },
            "display_resolution": "1920x1080",
            "document_id": "3350f1da-fa39-4415-b2cc-02057e2fbe99",
            "domain": "example1.com",
            "email": {
                "domain": "example.com",
                "username": "john.doe",
                "value": "john.doe@example.com"
            },
            "first_name": "John",
            "full_name": "John Doe",
            "homepage": "https://www.chess.com/member/sarahjoh",
            "industry": "Technology",
            "infected": {
                "machine_id": "ABC123",
                "path": "/documents/confidential",
                "time": "2023-01-15T12:30:45.000Z"
            },
            "ip_addresses": [
                "89.160.20.128",
                "89.160.20.112"
            ],
            "job_title": "Software Engineer",
            "keyboard_languages": [
                "English",
                "Spanish"
            ],
            "last_name": "Doe",
            "log_id": "76afa48107ec32f51a2aba4a314357c1e69d2267f1b04bf1afc948d0f77b1658",
            "password": {
                "plaintext": "REDACTED",
                "type": "alphanumeric",
                "value": "REDACTED"
            },
            "record": {
                "addition_date": "2023-12-06T00:00:00.000Z",
                "cracked_date": "2023-11-29T00:00:00.000Z",
                "modification_date": "2023-11-29T00:00:00.000Z"
            },
            "salt": "fbbdhd",
            "severity": 3,
            "sighting": 17,
            "social_linkedin": [
                "ildar-bazanov-961b14160"
            ],
            "source_id": "50436",
            "spycloud_publish_date": "2023-01-20T08:00:00.000Z",
            "target": {
                "domain": "example.com",
                "subdomain": "login.example.com",
                "url": "https://example.com/login"
            },
            "user": {
                "browser": "Chrome",
                "hostname": "workstation-1",
                "name": "john_doe",
                "os": "Windows 10",
                "sys": {
                    "domain": "8ad8.default",
                    "registered_owner": "John Milk"
                }
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "hide_sensitive",
        "forwarded",
        "spycloud-breach_record"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com/login",
        "path": "/login",
        "scheme": "https"
    },
    "user": {
        "domain": "example1.com",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "name": "john_doe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| spycloud.breach_record.account.image_url | The URL pointing to the user's account image or avatar. | keyword |
| spycloud.breach_record.account.login_time | The timestamp indicating the last time the account was logged into. | date |
| spycloud.breach_record.account.modification_time | The timestamp indicating the last time modifications were made to the account details. | date |
| spycloud.breach_record.account.signup_time | The date and time when the user's account was created or signed up. | date |
| spycloud.breach_record.av_softwares | Indicates the antivirus software or security programs installed on the compromised system. It is represented as an array of strings. | keyword |
| spycloud.breach_record.cc.bin | The Bank Identification Number (BIN) of a credit card, which identifies the issuer of the card. | keyword |
| spycloud.breach_record.cc.expiration | The expiration date of a credit card. | keyword |
| spycloud.breach_record.cc.last_four | The last four digits of the credit card number. | keyword |
| spycloud.breach_record.cc.number | The credit card number, possibly encrypted or hashed for security. | keyword |
| spycloud.breach_record.company_name | The name of the company or organization associated with the user. | keyword |
| spycloud.breach_record.country.code | Represents the country code associated with the compromised account. | keyword |
| spycloud.breach_record.country.name | Indicates the country associated with the compromised account. | keyword |
| spycloud.breach_record.display_resolution | Indicates the display resolution settings associated with the compromised device. | keyword |
| spycloud.breach_record.document_id | Identifier for the compromised document or file. | keyword |
| spycloud.breach_record.domain | Represents the compromised domain. | keyword |
| spycloud.breach_record.email.domain | Represents the domain part of the compromised email address. | keyword |
| spycloud.breach_record.email.username | Represents the username part of the compromised email address. | keyword |
| spycloud.breach_record.email.value | Represents the compromised email address. | keyword |
| spycloud.breach_record.first_name | The first name of the user. | keyword |
| spycloud.breach_record.full_name | The full name associated with the compromised account. | keyword |
| spycloud.breach_record.homepage | The URL of the user's homepage or profile page. | keyword |
| spycloud.breach_record.industry | The industry or sector to which the user or their associated company belongs. | keyword |
| spycloud.breach_record.infected.machine_id | Identifier for the compromised machine or device. | keyword |
| spycloud.breach_record.infected.path | Describes the path or location where the compromise or infection occurred. | keyword |
| spycloud.breach_record.infected.time | Represents the timestamp or time of the compromise event. | date |
| spycloud.breach_record.ip_addresses | Refers to the compromised IP addresses associated with the account. It is represented as an array of strings. | ip |
| spycloud.breach_record.job_title | The job title or position held by the user within their company or organization. | keyword |
| spycloud.breach_record.keyboard_languages | Represents the keyboard languages associated with the compromised account. | keyword |
| spycloud.breach_record.last_name | The last name or surname of the user. | keyword |
| spycloud.breach_record.log_id | Identifier for the log or record of the compromise event. | keyword |
| spycloud.breach_record.password.plaintext | Plaintext password. | keyword |
| spycloud.breach_record.password.type | Describes the type or nature of the compromised password (e.g., alphanumeric, special characters). | keyword |
| spycloud.breach_record.password.value | Represents the compromised password associated with the account. | keyword |
| spycloud.breach_record.record.addition_date | The date when the record associated with the account was added to the watchlist. | date |
| spycloud.breach_record.record.cracked_date | The date when the record associated with the account was cracked or compromised. | date |
| spycloud.breach_record.record.modification_date | The date when the record associated with the account was last modified. | date |
| spycloud.breach_record.salt | A randomly generated value used in cryptographic processes to enhance security, often combined with other data for hashing. | keyword |
| spycloud.breach_record.severity | Indicates the severity level or impact of the compromise. It is represented as an integer. | long |
| spycloud.breach_record.sighting | Indicates the sighting of the compromised information. | long |
| spycloud.breach_record.social_linkedin | This field contains LinkedIn profile information associated with the individual in the watchlist. | keyword |
| spycloud.breach_record.source_id | Identifier for the data source or origin of the compromised information. | keyword |
| spycloud.breach_record.spycloud_publish_date | The date when the information was published by SpyCloud. | date |
| spycloud.breach_record.target.domain | Indicates the domain targeted or affected by the compromise. | keyword |
| spycloud.breach_record.target.subdomain | Represents the subdomain targeted or affected by the compromise. | keyword |
| spycloud.breach_record.target.url | Refers to the URL or web address targeted or affected by the compromise. | keyword |
| spycloud.breach_record.user.browser | Indicates the web browser associated with the compromised account. | keyword |
| spycloud.breach_record.user.hostname | The hostname of the compromised user system. | keyword |
| spycloud.breach_record.user.name | The username associated with the compromised account. | keyword |
| spycloud.breach_record.user.os | Represents the operating system of the compromised device. | keyword |
| spycloud.breach_record.user.sys.domain | The domain associated with the user system. | keyword |
| spycloud.breach_record.user.sys.registered_owner | Represents the registered owner of the compromised system. | keyword |
| tags | User defined tags. | keyword |


### Compass

This is the `Compass` dataset.

#### Example

An example event for `compass` looks as following:

```json
{
    "@timestamp": "2022-11-17T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "7f89a7df-dbc1-419e-8862-9c4bce1e20ca",
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spycloud.compass",
        "namespace": "63821",
        "type": "logs"
    },
    "destination": {
        "domain": "sparefactor.com",
        "subdomain": "application.sparefactor.com"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "763d7558-f93b-440a-94ee-509804901acf",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spycloud.compass",
        "id": "3807a672-e5c4-4a58-8ade-93a690136c24",
        "ingested": "2024-08-16T06:25:25Z",
        "kind": "event",
        "original": "{\"av_softwares\":[\"Windows Defender\"],\"country\":\"PHILIPPINES\",\"country_code\":\"PH\",\"document_id\":\"3807a672-e5c4-4a58-8ade-93a690136c24\",\"domain\":\"gmail.com\",\"email\":\"wer****************r@gmail.com\",\"email_domain\":\"gmail.com\",\"email_username\":\"wer****************r\",\"infected_machine_id\":\"76c9a60b-1d06-4bc1-8e08-4f07f82c0bdd\",\"infected_path\":\"C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\AppLaunch.exe\",\"infected_time\":\"2022-08-11T18:02:31Z\",\"ip_addresses\":[\"110.18.12.120\"],\"keyboard_languages\":\"english (united states)\",\"log_id\":\"fc201cf30d2727c57f07f05f3ab6ee43c7260609d973d508f818c1abcc4fcb39\",\"password\":\"********\",\"password_plaintext\":\"********\",\"password_type\":\"plaintext\",\"severity\":25,\"source_id\":40351,\"spycloud_publish_date\":\"2022-11-17T00:00:00Z\",\"target_domain\":\"sparefactor.com\",\"target_subdomain\":\"application.sparefactor.com\",\"target_url\":\"application.sparefactor.com\",\"user_browser\":\"Google Chrome [Default]\",\"user_hostname\":\"LAPTOP-4G2P1N13\",\"user_os\":\"Windows 10 Home Single Language [x64]\",\"user_sys_registered_owner\":\"NewAdmin\"}",
        "severity": 25
    },
    "host": {
        "geo": {
            "country_iso_code": "PH",
            "country_name": "PHILIPPINES"
        },
        "hostname": "LAPTOP-4G2P1N13",
        "ip": [
            "110.18.12.120"
        ],
        "os": {
            "full": "Windows 10 Home Single Language [x64]",
            "type": "windows"
        }
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "LAPTOP-4G2P1N13",
            "Windows 10 Home Single Language [x64]"
        ],
        "ip": [
            "110.18.12.120"
        ],
        "user": [
            "gmail.com",
            "wer****************r",
            "NewAdmin"
        ]
    },
    "spycloud": {
        "compass": {
            "av_softwares": [
                "Windows Defender"
            ],
            "country": {
                "code": "PH",
                "name": "PHILIPPINES"
            },
            "document_id": "3807a672-e5c4-4a58-8ade-93a690136c24",
            "domain": "gmail.com",
            "email": {
                "domain": "gmail.com",
                "username": "wer****************r",
                "value": "wer****************r@gmail.com"
            },
            "infected": {
                "machine_id": "76c9a60b-1d06-4bc1-8e08-4f07f82c0bdd",
                "path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe",
                "time": "2022-08-11T18:02:31.000Z"
            },
            "ip_addresses": [
                "110.18.12.120"
            ],
            "keyboard_languages": "english (united states)",
            "log_id": "fc201cf30d2727c57f07f05f3ab6ee43c7260609d973d508f818c1abcc4fcb39",
            "password": {
                "plaintext": "REDACTED",
                "type": "plaintext",
                "value": "REDACTED"
            },
            "severity": 25,
            "source_id": "40351",
            "spycloud_publish_date": "2022-11-17T00:00:00.000Z",
            "target": {
                "domain": "sparefactor.com",
                "subdomain": "application.sparefactor.com",
                "url": "application.sparefactor.com"
            },
            "user": {
                "browser": "Google Chrome [Default]",
                "hostname": "LAPTOP-4G2P1N13",
                "os": "Windows 10 Home Single Language [x64]",
                "sys": {
                    "registered_owner": "NewAdmin"
                }
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "hide_sensitive",
        "forwarded",
        "spycloud-compass"
    ],
    "url": {
        "extension": "com",
        "original": "application.sparefactor.com",
        "path": "application.sparefactor.com"
    },
    "user": {
        "domain": "gmail.com",
        "email": "wer****************r@gmail.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| spycloud.compass.av_softwares | List of antivirus software installed on the machine. | keyword |
| spycloud.compass.backup.email.username | The username associated with the backup email. | keyword |
| spycloud.compass.backup.email.value | The email address used for backup or recovery purposes. | keyword |
| spycloud.compass.bank_number | The bank account number. | keyword |
| spycloud.compass.cc.bin | The Bank Identification Number (BIN) of a credit card. | keyword |
| spycloud.compass.cc.expiration | The expiration date of a credit card. | keyword |
| spycloud.compass.cc.last_four | The last four digits of the credit card number. | keyword |
| spycloud.compass.cc.number | The credit card number, possibly encrypted or hashed for security. | keyword |
| spycloud.compass.country.code | The country code associated with the user. | keyword |
| spycloud.compass.country.name | The country associated with the user. | keyword |
| spycloud.compass.display_resolution | The screen resolution settings of the user's display. | keyword |
| spycloud.compass.document_id | Identifier for a specific document. | keyword |
| spycloud.compass.domain | The domain associated with the user. | keyword |
| spycloud.compass.drivers.license.number | The driver's license number of the user. | keyword |
| spycloud.compass.drivers.license.state_code | The state code associated with the user's driver's license. | keyword |
| spycloud.compass.email.domain | The domain part of the email address. | keyword |
| spycloud.compass.email.username | The username part of the email address. | keyword |
| spycloud.compass.email.value | The email address associated with the account. | keyword |
| spycloud.compass.full_name | The full name of the user. | keyword |
| spycloud.compass.homepage | The URL of the user's homepage or website. | keyword |
| spycloud.compass.infected.machine_id | Identifier for the infected machine. | keyword |
| spycloud.compass.infected.path | The path or location on the machine where the infection occurred. | keyword |
| spycloud.compass.infected.time | Timestamp indicating when the infection occurred. | date |
| spycloud.compass.ip_addresses | List of IP addresses associated with the user. | ip |
| spycloud.compass.keyboard_languages | The languages configured on the keyboard. | keyword |
| spycloud.compass.log_id | Identifier for a log entry. | keyword |
| spycloud.compass.national_id | The national identification number of the user. | keyword |
| spycloud.compass.passport_number | The passport number of the user. | keyword |
| spycloud.compass.password.plaintext | Plaintext password. | keyword |
| spycloud.compass.password.type | Type or classification of the password. | keyword |
| spycloud.compass.password.value | Encrypted or hashed form of the user's password. | keyword |
| spycloud.compass.postal_code | The postal code associated with the user's address. | keyword |
| spycloud.compass.severity | The severity level of the security event or compromise. | long |
| spycloud.compass.social_security_number | The Social Security Number (SSN) of the user, possibly encrypted or hashed. | keyword |
| spycloud.compass.source_id | Identifier for the data source. | keyword |
| spycloud.compass.spycloud_publish_date | The date when the data was published by SpyCloud. | date |
| spycloud.compass.ssn_last_four | The last four digits of the Social Security Number (SSN). | keyword |
| spycloud.compass.target.domain | The domain that was targeted or affected. | keyword |
| spycloud.compass.target.subdomain | The subdomain that was targeted or affected. | keyword |
| spycloud.compass.target.url | The URL that was targeted or affected. | keyword |
| spycloud.compass.user.browser | The web browser used by the user. | keyword |
| spycloud.compass.user.hostname | The hostname of the user's machine. | keyword |
| spycloud.compass.user.name | The username associated with the account. | keyword |
| spycloud.compass.user.os | The operating system used by the user. | keyword |
| spycloud.compass.user.sys.domain | The system domain associated with the user. | keyword |
| spycloud.compass.user.sys.registered_owner | The registered owner of the user's system. | keyword |
| tags | User defined tags. | keyword |

