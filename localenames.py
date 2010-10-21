# -*- coding: utf-8 -*-
## borrowed from gettext sources, in itself based on ISO 639
## http://www.w3.org/WAI/ER/IG/ert/iso639.htm

localenames = [
     "Afrikaans",
     "Albanian",
     "Amharic",
     "Arabic",
     "Armenian",
     "Assamese",
     "Aymara",
     "Azerbaijani",
     "Basque",
     "Belarusian",
     "Belorussian",
     "Bengali",
     "Brazilian Portugese",
     "Brazilian Portuguese",
     "Breton",
     "Bulgarian",
     "Burmese",
     "Byelorussian",
     "Catalan",
     "Chewa",
     "Chichewa",
     "Chinese",
     "Chinese, Simplified",
     "Chinese, Traditional",
     "Chinese, Tradtional",
     "Croatian",
     "Czech",
     "Danish",
     "Dutch",
     "Dzongkha",
     "English",
     "Esperanto",
     "Estonian",
     "Faroese",
     "Farsi",
     "Finnish",
     "Flemish",
     "French",
     "Galician",
     "Gallegan",
     "Georgian",
     "German",
     "Greek",
     "Greenlandic",
     "Guarani",
     "Gujarati",
     "Hawaiian",
     "Hebrew",
     "Hindi",
     "Hungarian",
     "Icelandic",
     "Indonesian",
     "Inuktitut",
     "Irish",
     "Italian",
     "Japanese",
     "Javanese",
     "Kalaallisut",
     "Kannada",
     "Kashmiri",
     "Kazakh",
     "Khmer",
     "Kinyarwanda",
     "Kirghiz",
     "Korean",
     "Kurdish",
     "Latin",
     "Latvian",
     "Lithuanian",
     "Macedonian",
     "Malagasy",
     "Malay",
     "Malayalam",
     "Maltese",
     "Manx",
     "Marathi",
     "Moldavian",
     "Mongolian",
     "Nepali",
     "Norwegian",
     "Nyanja",
     "Nynorsk",
     "Oriya",
     "Oromo",
     "Panjabi",
     "Pashto",
     "Persian",
     "Polish",
     "Portuguese",
     "Portuguese, Brazilian",
     "Punjabi",
     "Pushto",
     "Quechua",
     "Romanian",
     "Ruanda",
     "Rundi",
     "Russian",
     "Sami",
     "Sanskrit",
     "Scottish",
     "Serbian",
     "Simplified Chinese",
     "Sindhi",
     "Sinhalese",
     "Slovak",
     "Slovenian",
     "Somali",
     "Spanish",
     "Sundanese",
     "Swahili",
     "Swedish",
     "Tagalog",
     "Tajik",
     "Tajiki",
     "Tamil",
     "Tatar",
     "Telugu",
     "Thai",
     "Tibetan",
     "Tigrinya",
     "Tongan",
     "Traditional Chinese",
     "Turkish",
     "Turkmen",
     "Uighur",
     "Ukrainian",
     "Urdu",
     "Uzbek",
     "Vietnamese",
     "Welsh",
     "Yiddish"
       ]

## list of encodings and character sets, from various places in gettext and vim

charsets = [ "ANSI_X3.4-1968",
    "ASCII",
    "EBCDIC",
    "US-ASCII",
    "ISO-8859-1",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "ISO-8859-13",
    "ISO-8859-14",
    "ISO-8859-15",
    "KOI8-R",
    "KOI8-U",
    "KOI8-T",
    "CP850",
    "CP866",
    "CP874",
    "CP932",
    "CP936",
    "CP949",
    "CP950",
    "CP1250",
    "CP1251",
    "CP1252",
    "CP1253",
    "CP1254",
    "CP1255",
    "CP1256",
    "CP1257",
    "GB2312",
    "EUC-JP",
    "EUC-KR",
    "EUC-TW",
    "BIG5",
    "BIG5-HKSCS",
    "GBK",
    "GB18030",
    "SHIFT_JIS",
    "JOHAB",
    "TIS-620",
    "VISCII",
    "GEORGIAN-PS",
    "CP1361",
    "CP20127",
    "CP20866",
    "CP20936",
    "CP21866",
    "CP28591",
    "CP28592",
    "CP28593",
    "CP28594",
    "CP28595",
    "CP28596",
    "CP28597",
    "CP28598",
    "CP28599",
    "CP28605",
    "CP38598",
    "CP51932",
    "CP51936",
    "CP51949",
    "CP51950",
    "CP54936",
    "CP65001"
           ]

## TODO: country names from ISO 3166
countrynames = [ "Afghanistan"
               , "Islamic Republic of Afghanistan"
               , "Åland Islands"
               , "Albania"
               , "Republic of Albania"
               , "Algeria"
               , "People's Democratic Republic of Algeria"
               , "American Samoa"
               , "Andorra"
               , "Principality of Andorra"
               , "Angola"
               , "Republic of Angola"
               , "Anguilla"
               , "Antarctica"
               , "Antigua and Barbuda"
               , "Argentina"
               , "Argentine Republic"
               , "Armenia"
               , "Republic of Armenia"
               , "Aruba"
               , "Australia"
               , "Austria"
               , "Republic of Austria"
               , "Azerbaijan"
               , "Republic of Azerbaijan"
               , "Bahamas"
               , "Commonwealth of the Bahamas"
               , "Bahrain"
               , "Kingdom of Bahrain"
               , "Bangladesh"
               , "People's Republic of Bangladesh"
               , "Barbados"
               , "Belarus"
               , "Republic of Belarus"
               , "Belgium"
               , "Kingdom of Belgium"
               , "Belize"
               , "Benin"
               , "Republic of Benin"
               , "Bermuda"
               , "Bhutan"
               , "Kingdom of Bhutan"
               , "Bolivia"
               , "Bolivia, Plurinational State of"
               , "Plurinational State of Bolivia"
               , "Bosnia and Herzegovina"
               , "Republic of Bosnia and Herzegovina"
               , "Botswana"
               , "Republic of Botswana"
               , "Bouvet Island"
               , "Brazil"
               , "Federative Republic of Brazil"
               , "British Indian Ocean Territory"
               , "Brunei Darussalam"
               , "Bulgaria"
               , "Republic of Bulgaria"
               , "Burkina Faso"
               , "Burundi"
               , "Republic of Burundi"
               , "Cambodia"
               , "Kingdom of Cambodia"
               , "Cameroon"
               , "Republic of Cameroon"
               , "Canada"
               , "Cape Verde"
               , "Republic of Cape Verde"
               , "Cayman Islands"
               , "Central African Republic"
               , "Chad"
               , "Republic of Chad"
               , "Chile"
               , "Republic of Chile"
               , "China"
               , "People's Republic of China"
               , "Christmas Island"
               , "Cocos (Keeling) Islands"
               , "Colombia"
               , "Republic of Colombia"
               , "Comoros"
               , "Union of the Comoros"
               , "Congo"
               , "Republic of the Congo"
               , "Congo, The Democratic Republic of the"
               , "Cook Islands"
               , "Costa Rica"
               , "Republic of Costa Rica"
               , "Côte d'Ivoire"
               , "Republic of Côte d'Ivoire"
               , "Croatia"
               , "Republic of Croatia"
               , "Cuba"
               , "Republic of Cuba"
               , "Cyprus"
               , "Republic of Cyprus"
               , "Czech Republic"
               , "Denmark"
               , "Kingdom of Denmark"
               , "Djibouti"
               , "Republic of Djibouti"
               , "Dominica"
               , "Commonwealth of Dominica"
               , "Dominican Republic"
               , "Ecuador"
               , "Republic of Ecuador"
               , "Egypt"
               , "Arab Republic of Egypt"
               , "El Salvador"
               , "Republic of El Salvador"
               , "Equatorial Guinea"
               , "Republic of Equatorial Guinea"
               , "Eritrea"
               , "Estonia"
               , "Republic of Estonia"
               , "Ethiopia"
               , "Federal Democratic Republic of Ethiopia"
               , "Falkland Islands (Malvinas)"
               , "Faroe Islands"
               , "Fiji"
               , "Republic of the Fiji Islands"
               , "Finland"
               , "Republic of Finland"
               , "France"
               , "French Republic"
               , "French Guiana"
               , "French Polynesia"
               , "French Southern Territories"
               , "Gabon"
               , "Gabonese Republic"
               , "Gambia"
               , "Republic of the Gambia"
               , "Georgia"
               , "Germany"
               , "Federal Republic of Germany"
               , "Ghana"
               , "Republic of Ghana"
               , "Gibraltar"
               , "Greece"
               , "Hellenic Republic"
               , "Greenland"
               , "Grenada"
               , "Guadeloupe"
               , "Guam"
               , "Guatemala"
               , "Republic of Guatemala"
               , "Guernsey"
               , "Guinea"
               , "Republic of Guinea"
               , "Guinea-Bissau"
               , "Republic of Guinea-Bissau"
               , "Guyana"
               , "Republic of Guyana"
               , "Haiti"
               , "Republic of Haiti"
               , "Heard Island and McDonald Islands"
               , "Holy See (Vatican City State)"
               , "Honduras"
               , "Republic of Honduras"
               , "Hong Kong"
               , "Hong Kong Special Administrative Region of China"
               , "Hungary"
               , "Republic of Hungary"
               , "Iceland"
               , "Republic of Iceland"
               , "India"
               , "Republic of India"
               , "Indonesia"
               , "Republic of Indonesia"
               , "Iran, Islamic Republic of"
               , "Islamic Republic of Iran"
               , "Iraq"
               , "Republic of Iraq"
               , "Ireland"
               , "Isle of Man"
               , "Israel"
               , "State of Israel"
               , "Italy"
               , "Italian Republic"
               , "Jamaica"
               , "Japan"
               , "Jersey"
               , "Jordan"
               , "Hashemite Kingdom of Jordan"
               , "Kazakhstan"
               , "Republic of Kazakhstan"
               , "Kenya"
               , "Republic of Kenya"
               , "Kiribati"
               , "Republic of Kiribati"
               , "Korea, Democratic People's Republic of"
               , "Democratic People's Republic of Korea"
               , "Korea, Republic of"
               , "Kuwait"
               , "State of Kuwait"
               , "Kyrgyzstan"
               , "Kyrgyz Republic"
               , "Lao People's Democratic Republic"
               , "Latvia"
               , "Republic of Latvia"
               , "Lebanon"
               , "Lebanese Republic"
               , "Lesotho"
               , "Kingdom of Lesotho"
               , "Liberia"
               , "Republic of Liberia"
               , "Libya"
               , "Libyan Arab Jamahiriya"
               , "Socialist People's Libyan Arab Jamahiriya"
               , "Liechtenstein"
               , "Principality of Liechtenstein"
               , "Lithuania"
               , "Republic of Lithuania"
               , "Luxembourg"
               , "Grand Duchy of Luxembourg"
               , "Macao"
               , "Macao Special Administrative Region of China"
               , "Macedonia, Republic of"
               , "The Former Yugoslav Republic of Macedonia"
               , "Madagascar"
               , "Republic of Madagascar"
               , "Malawi"
               , "Republic of Malawi"
               , "Malaysia"
               , "Maldives"
               , "Republic of Maldives"
               , "Mali"
               , "Republic of Mali"
               , "Malta"
               , "Republic of Malta"
               , "Marshall Islands"
               , "Republic of the Marshall Islands"
               , "Martinique"
               , "Mauritania"
               , "Islamic Republic of Mauritania"
               , "Mauritius"
               , "Republic of Mauritius"
               , "Mayotte"
               , "Mexico"
               , "United Mexican States"
               , "Micronesia, Federated States of"
               , "Federated States of Micronesia"
               , "Moldova"
               , "Moldova, Republic of"
               , "Republic of Moldova"
               , "Monaco"
               , "Principality of Monaco"
               , "Mongolia"
               , "Montenegro"
               , "Montenegro"
               , "Montserrat"
               , "Morocco"
               , "Kingdom of Morocco"
               , "Mozambique"
               , "Republic of Mozambique"
               , "Myanmar"
               , "Union of Myanmar"
               , "Namibia"
               , "Republic of Namibia"
               , "Nauru"
               , "Republic of Nauru"
               , "Nepal"
               , "Federal Democratic Republic of Nepal"
               , "Netherlands"
               , "Kingdom of the Netherlands"
               , "Netherlands Antilles"
               , "New Caledonia"
               , "New Zealand"
               , "Nicaragua"
               , "Republic of Nicaragua"
               , "Niger"
               , "Republic of the Niger"
               , "Nigeria"
               , "Federal Republic of Nigeria"
               , "Niue"
               , "Republic of Niue"
               , "Norfolk Island"
               , "Northern Mariana Islands"
               , "Commonwealth of the Northern Mariana Islands"
               , "Norway"
               , "Kingdom of Norway"
               , "Oman"
               , "Sultanate of Oman"
               , "Pakistan"
               , "Islamic Republic of Pakistan"
               , "Palau"
               , "Republic of Palau"
               , "Palestinian Territory, Occupied"
               , "Occupied Palestinian Territory"
               , "Panama"
               , "Republic of Panama"
               , "Papua New Guinea"
               , "Paraguay"
               , "Republic of Paraguay"
               , "Peru"
               , "Republic of Peru"
               , "Philippines"
               , "Republic of the Philippines"
               , "Pitcairn"
               , "Poland"
               , "Republic of Poland"
               , "Portugal"
               , "Portuguese Republic"
               , "Puerto Rico"
               , "Qatar"
               , "State of Qatar"
               , "Reunion"
               , "Romania"
               , "Russian Federation"
               , "Rwanda"
               , "Rwandese Republic"
               , "Saint Barthélemy"
               , "Saint Helena, Ascension and Tristan da Cunha"
               , "Saint Kitts and Nevis"
               , "Saint Lucia"
               , "Saint Martin (French part)"
               , "Saint Pierre and Miquelon"
               , "Saint Vincent and the Grenadines"
               , "Samoa"
               , "Independent State of Samoa"
               , "San Marino"
               , "Republic of San Marino"
               , "Sao Tome and Principe"
               , "Democratic Republic of Sao Tome and Principe"
               , "Saudi Arabia"
               , "Kingdom of Saudi Arabia"
               , "Senegal"
               , "Republic of Senegal"
               , "Serbia"
               , "Republic of Serbia"
               , "Seychelles"
               , "Republic of Seychelles"
               , "Sierra Leone"
               , "Republic of Sierra Leone"
               , "Singapore"
               , "Republic of Singapore"
               , "Slovakia"
               , "Slovak Republic"
               , "Slovenia"
               , "Republic of Slovenia"
               , "Solomon Islands"
               , "Somalia"
               , "Somali Republic"
               , "South Africa"
               , "Republic of South Africa"
               , "South Georgia and the South Sandwich Islands"
               , "Spain"
               , "Kingdom of Spain"
               , "Sri Lanka"
               , "Democratic Socialist Republic of Sri Lanka"
               , "Sudan"
               , "Republic of the Sudan"
               , "Suriname"
               , "Republic of Suriname"
               , "Svalbard and Jan Mayen"
               , "Swaziland"
               , "Kingdom of Swaziland"
               , "Sweden"
               , "Kingdom of Sweden"
               , "Switzerland"
               , "Swiss Confederation"
               , "Syrian Arab Republic"
               , "Taiwan"
               , "Taiwan, Province of China"
               , "Taiwan, Province of China"
               , "Tajikistan"
               , "Republic of Tajikistan"
               , "Tanzania, United Republic of"
               , "United Republic of Tanzania"
               , "Thailand"
               , "Kingdom of Thailand"
               , "Timor-Leste"
               , "Democratic Republic of Timor-Leste"
               , "Togo"
               , "Togolese Republic"
               , "Tokelau"
               , "Tonga"
               , "Kingdom of Tonga"
               , "Trinidad and Tobago"
               , "Republic of Trinidad and Tobago"
               , "Tunisia"
               , "Republic of Tunisia"
               , "Turkey"
               , "Republic of Turkey"
               , "Turkmenistan"
               , "Turks and Caicos Islands"
               , "Tuvalu"
               , "Uganda"
               , "Republic of Uganda"
               , "Ukraine"
               , "United Arab Emirates"
               , "United Kingdom"
               , "United Kingdom of Great Britain and Northern Ireland"
               , "United States"
               , "United States of America"
               , "United States Minor Outlying Islands"
               , "Uruguay"
               , "Eastern Republic of Uruguay"
               , "Uzbekistan"
               , "Republic of Uzbekistan"
               , "Vanuatu"
               , "Republic of Vanuatu"
               , "Venezuela"
               , "Venezuela, Bolivarian republic of"
               , "Bolivarian Republic of Venezuela"
               , "Viet Nam"
               , "Socialist Republic of Viet Nam"
               , "Virgin Islands, British"
               , "British Virgin Islands"
               , "Virgin Islands, U.S."
               , "Virgin Islands of the United States"
               , "Wallis and Futuna"
               , "Western Sahara"
               , "Yemen"
               , "Republic of Yemen"
               , "Zambia"
               , "Republic of Zambia"
               , "Zimbabwe"
               , "Republic of Zimbabwe"
               , "British Antarctic Territory"
               , "Burma, Socialist Republic of the Union of"
               , "Byelorussian SSR Soviet Socialist Republic"
               , "Canton and Enderbury Islands"
               , "Czechoslovakia, Czechoslovak Socialist Republic"
               , "Dahomey"
               , "Dronning Maud Land"
               , "East Timor"
               , "Ethiopia"
               , "France, Metropolitan"
               , "French Afars and Issas"
               , "French Southern and Antarctic Territories"
               , "German Democratic Republic"
               , "Germany, Federal Republic of"
               , "Gilbert and Ellice Islands"
               , "Johnston Island"
               , "Midway Islands"
               , "Netherlands Antilles"
               , "Neutral Zone"
               , "New Hebrides"
               , "Pacific Islands (trust territory)"
               , "Panama, Republic of"
               , "Panama Canal Zone"
               , "Romania, Socialist Republic of"
               , "St. Kitts-Nevis-Anguilla"
               , "Serbia and Montenegro"
               , "Sikkim"
               , "Southern Rhodesia"
               , "Spanish Sahara"
               , "US Miscellaneous Pacific Islands"
               , "USSR, Union of Soviet Socialist Republics"
               , "Upper Volta, Republic of"
               , "Vatican City State (Holy See)"
               , "Viet-Nam, Democratic Republic of"
               , "Wake Island"
               , "Yemen, Democratic, People's Democratic Republic of"
               , "Yemen, Yemen Arab Republic"
               , "Yugoslavia, Socialist Federal Republic of"
               , "Zaire, Republic of"
               ]
