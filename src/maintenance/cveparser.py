#!/usr/bin/env python

# Binary Analysis Tool
# Copyright 2015-2016 Armijn Hemel for Tjaldur Software Governance Solutions
# Licensed under Apache 2.0, see LICENSE file for details

'''
Script to process the CVE XML files. The input is a CVE file and a
configuration file with the locations of the database and a directory
to store patches listed in CVE reports.

The goal of this script is to link CVE reports to hashes in the BAT
database to help discover omissions in the CVE reports.

Documentation:

CPE specification: http://cpe.mitre.org/files/cpe-specification_2.1.pdf
CPE dictionary: https://cpe.mitre.org/dictionary/

Datafiles (version 2.0 of the format):

https://nvd.nist.gov/download.aspx
'''

import sys
import os
import re
from optparse import OptionParser
import ConfigParser
import xml.dom.minidom
import httplib
import batextensions
import psycopg2

batextensions = batextensions.extensions

# helper class to store software versions and add some crude comparison
# mechansim that should help comparing versions.
class softwareversion():
    def __init__(self, softwareversion):
        self.version = softwareversion
        self.majorversion = None
        self.minorversion = None
        self.subversion = None
        softwaresplits = softwareversion.split('.')
        if len(softwaresplits) == 2:
            try:
                self.majorversion = int(softwaresplits[0])
            except:
                self.majorversion = softwaresplits[0]
            try:
                self.minorversion = int(softwaresplits[1])
            except:
                self.minorversion = softwaresplits[1]
        if len(softwaresplits) == 3:
            try:
                self.majorversion = int(softwaresplits[0])
            except:
                self.majorversion = softwaresplits[0]
            try:
                self.minorversion = int(softwaresplits[1])
            except:
                self.minorversion = softwaresplits[1]
            try:
                self.subversion = int(softwaresplits[2])
            except:
                self.subversion = softwaresplits[2]
    def __lt__(self, other):
        # first check the major version
        if self.majorversion < other.majorversion:
            return True
        elif self.majorversion > other.majorversion:
            return False
        else:
            if type(other.minorversion) != int:
                # TODO: this needs a much better fix
                if "pre" in other.minorversion or "beta" in other.minorversion:
                    if other.minorversion.startswith(str(self.minorversion)):
                        return False
                if str(self.minorversion) < other.minorversion:
                    return True
                elif str(self.minorversion) > other.minorversion:
                    return False
            else:
                if self.minorversion < other.minorversion:
                    return True
                elif self.minorversion > other.minorversion:
                    return False
                else:
                    if self.subversion == None:
                        return False
                    if type(other.subversion) != int:
                        if str(self.subversion) < other.subversion:
                            return True
                        elif str(self.subversion) > other.subversion:
                            return False
                    else:
                        if self.subversion < other.subversion:
                            return True
                        elif self.subversion > other.subversion:
                            return False

# translation list for products and vendors used in CVE files
# origin in BAT database as generated by Tjaldur Software Governance Solutions
# TODO: only translate per product
vendortranslate = { 'haxx': {'curl': 'curl'}
                  , 'linux': {'linux_kernel': 'kernel'}
                  , 'oracle': {'mysql': 'mysql'}
                  , 'apple': {'cups': 'cups' }
                  , 'squid-cache': {'squid': 'squid' }
                  }
#
producttranslate = {'kernel': {'linux_kernel': 'linux'}
                   }

# combination of vendor/products to ignore for now
vendorproductignore = {}

# vendor {'product': [list of files to be ignored]}
vendorproductfileignore = {
      'curl': {
         'curl': ['include/curl/curlver.h', 'src/tool_version.h']
              }
                      }

def main(argv):
    config = ConfigParser.ConfigParser()
    optionparser = OptionParser()
    optionparser.add_option("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
    optionparser.add_option("-f", "--file", action="store", dest="cvefile", help="path to CVE file to process", metavar="FILE")
    (options, args) = optionparser.parse_args()

    if options.cvefile == None:
        optionparser.error("Specify CVE file to scan")

    if not os.path.exists(options.cvefile):
        print >>sys.stderr, "CVE file %s does not exist" % options.cvefile
        sys.exit(1)

    if options.cfg == None:
        optionparser.error("Specify configuration file")

    if not os.path.exists(options.cfg):
        optionparser.error("Configuration file does not exist")
    try:
        configfile = open(options.cfg, 'r')
    except:
        optionparser.error("Configuration file not readable")

    config.readfp(configfile)
    configfile.close()

    if not 'extractconfig' in config.sections():
        print >>sys.stderr, "malformed configuration file: 'extractconfig' section missing"
        sys.exit(1)

    if not 'cveconfig' in config.sections():
        print >>sys.stderr, "malformed configuration file: 'cveconfig' section missing"
        sys.exit(1)

    for section in config.sections():
        if section == 'extractconfig':
            try:
                postgresql_user = config.get(section, 'postgresql_user')
                postgresql_password = config.get(section, 'postgresql_password')
                postgresql_db = config.get(section, 'postgresql_db')

                # check to see if a host (IP-address) was supplied either
                # as host or hostaddr. hostaddr is not supported on older
                # versions of psycopg2, for example CentOS 6.6, so it is not
                # used at the moment.
                try:
                    postgresql_host = config.get(section, 'postgresql_host')
                except:
                    postgresql_host = None
                try:
                    postgresql_hostaddr = config.get(section, 'postgresql_hostaddr')
                except:
                    postgresql_hostaddr = None
                # check to see if a port was specified. If not, default to 'None'
                try:
                    postgresql_port = config.get(section, 'postgresql_port')
                except Exception, e:
                    postgresql_port = None
            except:
                print >>sys.stderr, "Database connection not defined in configuration file. Exiting..."
                sys.stderr.flush()
                sys.exit(1)
        elif section == 'cveconfig':
            try:
                patchdir = config.get(section, 'patchdir')
            except:
                print >>sys.stderr, "patchdir not specified in configuration file"
                sys.exit(1)

    try:
        conn = psycopg2.connect(database=postgresql_db, user=postgresql_user, password=postgresql_password, host=postgresql_host, port=postgresql_port)

        cursor = conn.cursor()
    except:
        print >>sys.stderr, "Can't open database"
        sys.exit(1)

    # TODO: more sanity checks
    if not os.path.exists(patchdir):
        print >>sys.stderr, "patchdir %s does not exist" % patchdir
        sys.exit(1)

    cursor.execute('select distinct(origin) from processed')
    origins = cursor.fetchall()
    conn.commit()
    origins = map(lambda x: x[0], origins)

    securitycursor = conn.cursor()
    # read the CVE file into a string
    cvestring = open(options.cvefile, 'rb').read()

    # then create a DOM of the CVE file
    dom = xml.dom.minidom.parseString(cvestring)

    # get all CVE elements from the DOM
    cves = dom.getElementsByTagName('entry')

    # process each CVE element stored in the XML file
    # store the following information per CVE report:
    # * cve-id
    # * vuln:vulnerable-software-list - product, vendor
    # * source of the vulnerability report (debian, red hat, fedora, etc.)
    for c in cves:
        # get the CVE ID
        if c.hasAttributes():
            cveid = c.getAttribute('id')
        vendorproduct = {}
        vulnpaths = set()
        patches = set()
        vulnerablechecksums = set()

        for ch in c.childNodes:
            if ch.nodeName == 'vuln:vulnerable-software-list':
                for vs in ch.childNodes:
                    if vs.nodeName == 'vuln:product':
                        splitdata = vs.childNodes[0].data.split(':')
                        # according to CPE documentation there is a maximum
                        # of 7 components (excluding the 'cpe' keyword)
                        if len(splitdata) > 8:
                            continue
                        # see if there is enough information available to work with
                        if len(splitdata) < 5:
                            continue
                        vendor = splitdata[2]
                        product = splitdata[3]

                        # sometimes there is a mismatch between information in the
                        # database and the information in the CVE report, so it needs
                        # to be translated first.
                        # Translations can be done on a few levels:
                        # 1. translate the vendor in the CVE report to origin in BAT database
                        # 2. translate a single vendor/product combination in the CVE
                        #    to an origin/product combination in BAT database
                        # 3. translate a prodct name from the CVE report CVE to a 
                        #    product name in the BAT database.
                        # TODO: better fix this
                        if vendor in vendortranslate:
                            if product in vendortranslate[vendor]:
                                vendor = vendortranslate[vendor][product]
                        if vendor in producttranslate:
                            if product in producttranslate[vendor]:
                                product = producttranslate[vendor][product]
                        if not vendor in vendorproduct:
                            vendorproduct[vendor] = {}
                        version = splitdata[4]
                        extraversion = None
                        if len(splitdata) > 5:
                            extraversion = splitdata[5]
                        if not product in vendorproduct[vendor]:
                            vendorproduct[vendor][product] = set()
                        vendorproduct[vendor][product].add((softwareversion(version), extraversion))

            # Then check if there are some references that can be
            # found, especially to Git repositories so patches can be downloaded
            # Currently only git.kernel.org and github are supported. Other Git
            # repositories still need to be added. As they are all a bit
            # different some custom code is needed.
            elif ch.nodeName == 'vuln:references':
                for vs in ch.childNodes:
                    if vs.nodeName == 'vuln:source':
                        source = vs.childNodes[0].data
                    elif vs.nodeName == 'vuln:reference':
                        if len(vs.childNodes) == 0:
                            continue
                        reference = vs.childNodes[0].data
                        outfilename = None
                        if reference.startswith('http://git.kernel.org/') or reference.startswith('https://git.kernel.org/'):
                            # The following assumes that the patchid can be found in for
                            # the following form (example from CVE-2010-1187:
                            # http://git.kernel.org/?p=linux/kernel/git/davem/net-2.6.git;a=commitdiff;h=d0021b252eaf65ca07ed14f0d66425dd9ccab9a6;hp=6d55cb91a0020ac0d78edcad61efd6c8cf5785a3
                            if '=' in reference:
                                patchid = reference.rsplit('=', 1)[-1]
                            else:
                                # example from CVE-2010-1188:
                                # http://git.kernel.org/linus/fb7e2399ec17f1004c0e0ccfd17439f8759ede01
                                patchid = reference.rsplit('/', 1)[-1]
                            patches.add(patchid)
                            outfilename = os.path.join(patchdir, patchid)
                            if not os.path.exists(outfilename):
                                if not "cgit" in reference:
                                    httpcon = httplib.HTTPConnection('git.kernel.org')
                                    httpcon.request('GET', reference)
                                    response = httpcon.getresponse()
                                    # hardcoded hack here to deal with git.kernel.org
                                    if response.status == 301:
                                        reference = response.getheader('Location')
                                    httpcon.close()

                                reference = reference.replace('/commit/', '/patch/')
                                httpcon = httplib.HTTPConnection('git.kernel.org')
                                httpcon.request('GET', reference)
                                filegrab = httpcon.getresponse()
                                patchdata = filegrab.read()
                                httpcon.close()
                                outfile = open(outfilename, 'w')
                                outfile.write(patchdata)
                                outfile.flush()
                                outfile.close()
                        elif reference.startswith('https://github.com/'):
                            if '/commit/' in reference:
                                patchid = reference.rsplit('/', 1)[-1]
                                if '#' in patchid:
                                    patchid = patchid.rsplit('#', 1)[0]
                                    reference = reference.rsplit('#', 1)[0]
                                patches.add(patchid)
                                outfilename = os.path.join(patchdir, patchid)
                                if not os.path.exists(outfilename):
                                    reference = reference + ".patch"
                                    httpcon = httplib.HTTPSConnection('github.com')
                                    httpcon.request('GET', reference)
                                    filegrab = httpcon.getresponse()
                                    if filegrab.status == 301:
                                        reference = filegrab.getheader('Location')
                                        httpcon.close()
                                        httpcon = httplib.HTTPSConnection('github.com')
                                        httpcon.request('GET', reference)
                                        filegrab = httpcon.getresponse()
                                    patchdata = filegrab.read()
                                    httpcon.close()
                                    if not "<h3>This repository is empty.</h3>" in patchdata:
                                        outfile = open(outfilename, 'w')
                                        outfile.write(patchdata)
                                        outfile.flush()
                                        outfile.close()
                                    else:
                                        outfilename = None
                        # As there is a patch file from Git this means
                        # that very likely it is possible to extract file
                        # names from the patch file that correspond to the
                        # vulnerable files
                        if outfilename != None:
                            gitfile = open(outfilename, 'rb')
                            gitlines = gitfile.readlines()
                            gitfile.close()
                            for gl in gitlines:
                                if not gl.startswith('diff --git a/'):
                                    continue
                                gitsplit = gl.split(' b/', 1)[0]
                                gitfilename = gitsplit.rsplit(' a/', 1)[1]
                                for e in batextensions.keys():
                                    if gitfilename.endswith(e):
                                        vulnpaths.add(gitfilename)
            # grab the human readable text and try to see if there
            # are any references to file names (found using extensions
            # in the BAT database) so there can be a mapping
            elif ch.nodeName == 'vuln:summary':
                vulndata = ch.childNodes[0].data
                vulndatasplits = vulndata.split()
                for e in batextensions.keys():
                    vulnpaths.update(filter(lambda x: x.lower().endswith(e), vulndatasplits))
                    if vulndatasplits[-1].endswith("%s." % e):
                        vulnpaths.add(vulndatasplits[-1][0:-1])

        if vendorproduct == {}:
            continue

        # process each result for each vendor
        for v in vendorproduct:
            for product in vendorproduct[v]:
                # first check whether or not the product is known
                # in the database by grabbing all the versions for
                # the product (per vendor/origin)
                cursor.execute("select version from processed where package=%s and origin=%s", (product, vendor))
                allversions = cursor.fetchall()
                conn.commit()
                if len(allversions) == 0:
                    continue

                allversions = map(lambda x: x[0], allversions)

                # Filter and store the versions that are not vulnerable
                vps = map(lambda x: x[0], filter(lambda x: x[1] == None, vendorproduct[v][product]))
                notvulnerable = list(set(allversions).difference(set(map(lambda x: x.version, vps))))
                notvulnerable.sort()

                # keep a set with checksums that are not vulnerable
                oldnotvulnchecksums = set()

                # store the lowest non-vulnerable version
                prevlowestnonvuln = None

                # create a list of vulnerable products, sorted by version number
                vproducts = list(vendorproduct[v][product])
                vproducts.sort(key=lambda x: x[0].version)
                checkedversions = set()
                if vproducts == []:
                    continue

                for vp in vproducts:
                    (version, extraversion) = vp
                    # some CVE reports list an extraversion. TODO: properly
                    # process these
                    if extraversion != None:
                        continue

                    # grab all the packages in the database with this version
                    cursor.execute("select package from processed where package=%s and version=%s", (product, version.version))
                    res = cursor.fetchone()
                    conn.commit()
                    if res == None:
                        continue
                    if version.version in checkedversions:
                        continue

                    # if any filenames could be extracted from the CVE report
                    # it is quite easy to find which files are vulnerable.
                    if len(vulnpaths) != 0:
                        for vulnpath in vulnpaths:
                            # First grab all the combinations of pathnames and checksums
                            # in the datbase that correspond to the package, version and
                            # filename (basename of vulnpath)
                            cursor.execute("select pathname, checksum from processed_file where package=%s and version=%s and filename=%s", (product, version.version, os.path.basename(vulnpath)))
                            vulnamechecksums = set(cursor.fetchall())
                            conn.commit()
                            for vulnamechecksum in vulnamechecksums:
                                match = False
                                # check if the names in the pathname in the database
                                # and the filename in the CVE report are close enough.
                                # Pathnames in the database will often have a version
                                # component that the CVE reports will not show in the
                                # filename.
                                if not '/' in vulnpath:
                                    pathcomponent = os.path.basename(vulnamechecksum[0])
                                    if vulnpath == pathcomponent:
                                        match = True
                                else:
                                    if vulnamechecksum[0].endswith(vulnpath):
                                        match = True
                                if match:
                                    # Add the vulnerable checksum to the list
                                    vulnerablechecksums.add(vulnamechecksum[1])
                                    # Now grab all package/version combinations
                                    # from the database with this database to see
                                    # which other packages and/or versions are
                                    # affected as well.
                                    cursor.execute("select package, version from processed_file where checksum=%s", (vulnamechecksum[1],))
                                    vulnpackageversions = cursor.fetchall()
                                    conn.commit()

                                    # grab all the vulnerable versions for this
                                    # particular product
                                    allvulnerableversions = map(lambda x: x[1], filter(lambda x: x[0] == product, vulnpackageversions))
                                    for vulpack in allvulnerableversions:
                                        checkedversions.add(vulpack)

                                    # It is easy to find other packages that use the
                                    # same file as well.
                                    #print "PACKAGES ALSO VULNERABLE for %s" % vulnamechecksum[1], filter(lambda x: x[0] != product, vulnpackageversions)

                        continue
                    break

                    # No names were mentioned in the report, so find the
                    # closest corresponding version that is not vulnerable
                    # and try to guess what the vulnerable files could have
                    # been. This is obviously less accurate than having a
                    # proper reference, as between versions many files could
                    # have changed, so there might be false positives.
                    # TODO: implement this

                if checkedversions != set():
                    # now record the checksum in the database
                    for vnl in vulnerablechecksums:
                        securitycursor.execute("insert into security_cve (checksum, cve) values (%s,%s)", (vnl, cveid))
                    conn.commit()

    securitycursor.close()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    main(sys.argv)
