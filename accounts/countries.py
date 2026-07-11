"""Country dial codes with ISO codes for real flag images (flagcdn.com)."""

# (iso2, dial_code, country_name)
COUNTRY_DIAL_CODES = [
    ("ke", "254", "Kenya"),
    ("ug", "256", "Uganda"),
    ("tz", "255", "Tanzania"),
    ("rw", "250", "Rwanda"),
    ("bi", "257", "Burundi"),
    ("et", "251", "Ethiopia"),
    ("so", "252", "Somalia"),
    ("dj", "253", "Djibouti"),
    ("ss", "211", "South Sudan"),
    ("sd", "249", "Sudan"),
    ("eg", "20", "Egypt"),
    ("za", "27", "South Africa"),
    ("ng", "234", "Nigeria"),
    ("gh", "233", "Ghana"),
    ("ci", "225", "Côte d'Ivoire"),
    ("sn", "221", "Senegal"),
    ("ma", "212", "Morocco"),
    ("dz", "213", "Algeria"),
    ("tn", "216", "Tunisia"),
    ("ly", "218", "Libya"),
    ("zm", "260", "Zambia"),
    ("zw", "263", "Zimbabwe"),
    ("mw", "265", "Malawi"),
    ("bw", "267", "Botswana"),
    ("na", "264", "Namibia"),
    ("mz", "258", "Mozambique"),
    ("ls", "266", "Lesotho"),
    ("sz", "268", "Eswatini"),
    ("mu", "230", "Mauritius"),
    ("sc", "248", "Seychelles"),
    ("us", "1", "United States"),
    ("ca", "1", "Canada"),
    ("gb", "44", "United Kingdom"),
    ("ie", "353", "Ireland"),
    ("fr", "33", "France"),
    ("de", "49", "Germany"),
    ("it", "39", "Italy"),
    ("es", "34", "Spain"),
    ("nl", "31", "Netherlands"),
    ("be", "32", "Belgium"),
    ("ch", "41", "Switzerland"),
    ("se", "46", "Sweden"),
    ("no", "47", "Norway"),
    ("dk", "45", "Denmark"),
    ("fi", "358", "Finland"),
    ("pl", "48", "Poland"),
    ("pt", "351", "Portugal"),
    ("gr", "30", "Greece"),
    ("tr", "90", "Turkey"),
    ("ru", "7", "Russia"),
    ("ua", "380", "Ukraine"),
    ("in", "91", "India"),
    ("pk", "92", "Pakistan"),
    ("bd", "880", "Bangladesh"),
    ("lk", "94", "Sri Lanka"),
    ("np", "977", "Nepal"),
    ("cn", "86", "China"),
    ("jp", "81", "Japan"),
    ("kr", "82", "South Korea"),
    ("sg", "65", "Singapore"),
    ("my", "60", "Malaysia"),
    ("th", "66", "Thailand"),
    ("id", "62", "Indonesia"),
    ("ph", "63", "Philippines"),
    ("vn", "84", "Vietnam"),
    ("hk", "852", "Hong Kong"),
    ("mo", "853", "Macau"),
    ("tw", "886", "Taiwan"),
    ("au", "61", "Australia"),
    ("nz", "64", "New Zealand"),
    ("br", "55", "Brazil"),
    ("ar", "54", "Argentina"),
    ("cl", "56", "Chile"),
    ("co", "57", "Colombia"),
    ("mx", "52", "Mexico"),
    ("pe", "51", "Peru"),
    ("ae", "971", "United Arab Emirates"),
    ("sa", "966", "Saudi Arabia"),
    ("qa", "974", "Qatar"),
    ("bh", "973", "Bahrain"),
    ("kw", "965", "Kuwait"),
    ("om", "968", "Oman"),
    ("il", "972", "Israel"),
    ("jo", "962", "Jordan"),
    ("lb", "961", "Lebanon"),
    ("sy", "963", "Syria"),
    ("iq", "964", "Iraq"),
    ("ir", "98", "Iran"),
]

FLAG_CDN = "https://flagcdn.com/w40/{iso}.png"
FLAG_CDN_2X = "https://flagcdn.com/w80/{iso}.png"

DEFAULT_COUNTRY = "254|Kenya"


def flag_url(iso2: str) -> str:
    return FLAG_CDN.format(iso=iso2.lower())


def country_choices():
    return [(f"{dial}|{name}", f"{name} (+{dial})") for iso, dial, name in COUNTRY_DIAL_CODES]


def get_country_options():
    options = []
    for iso, dial, name in COUNTRY_DIAL_CODES:
        options.append(
            {
                "iso": iso,
                "dial": dial,
                "name": name,
                "value": f"{dial}|{name}",
                "flag": flag_url(iso),
                "flag_2x": FLAG_CDN_2X.format(iso=iso.lower()),
                "label": f"{name} (+{dial})",
            }
        )
    return options


def dial_from_choice(value: str) -> str:
    if not value:
        return "254"
    return value.split("|", 1)[0]


def option_for_value(value: str):
    for opt in get_country_options():
        if opt["value"] == value:
            return opt
    return get_country_options()[0]
