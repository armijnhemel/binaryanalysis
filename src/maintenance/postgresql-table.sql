create table if not exists processed (package text, version text, filename text, origin text, checksum text, downloadurl text);
create table if not exists processed_file (package text, version text, pathname text, checksum text, filename text, thirdparty boolean);
create table if not exists extracted_string (stringidentifier text, checksum text, language text, linenumber int);
create table if not exists extracted_function (checksum text, functionname text, language text, linenumber int);
create table if not exists extracted_name (checksum text, name text, type text, language text, linenumber int);

create table if not exists kernel_configuration(configstring text, filename text, version text);
create table if not exists kernelmodule_alias(checksum text, modulename text, alias text);
create table if not exists kernelmodule_author(checksum text, modulename text, author text);
create table if not exists kernelmodule_description(checksum text, modulename text, description text);
create table if not exists kernelmodule_firmware(checksum text, modulename text, firmware text);
create table if not exists kernelmodule_license(checksum text, modulename text, license text);
create table if not exists kernelmodule_parameter(checksum text, modulename text, paramname text, paramtype text);
create table if not exists kernelmodule_parameter_description(checksum text, modulename text, paramname text, description text);
create table if not exists kernelmodule_version(checksum text, modulename text, version text);

create table if not exists rpm(rpmname text, checksum text, downloadurl text);
create table if not exists archivealias(checksum text, archivename text, origin text, downloadurl text);
create table if not exists misc(checksum text, name text);
create table if not exists hashconversion (sha256 text);
create table if not exists licenses (checksum text, license text, scanner text, version text);
create table if not exists extracted_copyright (checksum text, copyright text, type text, byteoffset int);
create table if not exists security_cert(checksum text, securitybug text, linenumber int, function text, whitelist boolean);
create table if not exists security_cve(checksum text, cve text);
create table if not exists security_password(hash text, password text);
create table if not exists renames (originalname text, newname text);
create table if not exists file(filename text, directory text, package text, packageversion text, source text, distroversion text);
create table if not exists stringscache_actionscript (stringidentifier text, package text, filename text);
create table if not exists scores_actionscript (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_actionscript (package text, avgstrings real, primary key (package));

create table if not exists stringscache_c (stringidentifier text, package text, filename text);
create table if not exists scores_c (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_c (package text, avgstrings real, primary key (package));

create table if not exists stringscache_csharp (stringidentifier text, package text, filename text);
create table if not exists scores_csharp (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_csharp (package text, avgstrings real, primary key (package));

create table if not exists stringscache_java (stringidentifier text, package text, filename text);
create table if not exists scores_java (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_java (package text, avgstrings real, primary key (package));

create table if not exists stringscache_javascript (stringidentifier text, package text, filename text);
create table if not exists scores_javascript (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_javascript (package text, avgstrings real, primary key (package));

create table if not exists stringscache_php (stringidentifier text, package text, filename text);
create table if not exists scores_php (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_php (package text, avgstrings real, primary key (package));

create table if not exists stringscache_python (stringidentifier text, package text, filename text);
create table if not exists scores_python (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_python (package text, avgstrings real, primary key (package));

create table if not exists stringscache_ruby (stringidentifier text, package text, filename text);
create table if not exists scores_ruby (stringidentifier text, packages int, score real);
create table if not exists avgstringscache_ruby (package text, avgstrings real, primary key (package));

create table if not exists varnamecache_c (varname text, package text);
create table if not exists linuxkernelnamecache (varname text, package text);
create table if not exists functionnamecache_c (functionname text, package text);
create table if not exists linuxkernelfunctionnamecache (functionname text, package text);
create table if not exists functionnamecache_java (functionname text, package text);
create table if not exists fieldcache_java (fieldname text, package text);
create table if not exists classcache_java (classname text, package text);
