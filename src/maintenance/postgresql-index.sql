create index processed_index on processed(package, version);
create index processed_checksum on processed(checksum);
create index processed_origin on processed(origin);
create index processedfile_package_checksum_index on processed_file(checksum, package);
create index processedfile_package_version_index on processed_file(package, version);
create index processedfile_filename_index on processed_file(filename);
create index stringidentifier_index on extracted_string(stringidentifier,language);
create index extracted_hash_index on extracted_string(checksum);
create index extracted_language_index on extracted_string(language);
create index function_index on extracted_function(checksum);
create index functionname_index on extracted_function(functionname);
create index functionname_language on extracted_function(language);
create index name_checksum_index on extracted_name(checksum);
create index name_name_index on extracted_name(name);
create index name_type_index on extracted_name(type);
create index name_language_index on extracted_name(language);
create index kernel_configuration_filename on kernel_configuration(filename);
create index kernelmodule_alias_index on kernelmodule_alias(alias);
create index kernelmodule_author_index on kernelmodule_author(author);
create index kernelmodule_description_index on kernelmodule_description(description);
create index kernelmodule_firmware_index on kernelmodule_firmware(firmware);
create index kernelmodule_license_index on kernelmodule_license(license);
create index kernelmodule_parameter_index on kernelmodule_parameter(paramname);
create index kernelmodule_parameter_description_index on kernelmodule_parameter_description(description);
create index kernelmodule_version_index on kernelmodule_version(version);
create index kernelmodule_alias_checksum_index on kernelmodule_alias(checksum);
create index kernelmodule_author_checksum_index on kernelmodule_author(checksum);
create index kernelmodule_description_checksum_index on kernelmodule_description(checksum);
create index kernelmodule_firmware_checksum_index on kernelmodule_firmware(checksum);
create index kernelmodule_license_checksum_index on kernelmodule_license(checksum);
create index kernelmodule_parameter_checksum_index on kernelmodule_parameter(checksum);
create index kernelmodule_parameter_description_checksum_index on kernelmodule_parameter_description(checksum);
create index kernelmodule_version_checksum_index on kernelmodule_version(checksum);
create index rpm_checksum_index on rpm(checksum);
create index rpm_rpmname_index on rpm(rpmname);
create index archivealias_checksum_index on archivealias(checksum);
create index misc_checksum_index on misc(checksum);
create index misc_name_index on misc(name);
create index hashconversion_sha256_index on hashconversion(sha256);
create index license_index on licenses(checksum);
create index copyright_index on extracted_copyright(checksum);
create index copyright_type_index on extracted_copyright(copyright, type);
create index security_cert_checksum_index on security_cert(checksum);
create index security_cve_checksum_index on security_cve(checksum);
create index security_password_hash_index on security_cve(checksum);
create index renames_index_originalname on renames (originalname);
create index renames_index_newname on renames (newname);
create index file_index on file(filename, directory);

create index linuxkernelfunctionname_index on linuxkernelfunctionnamecache(functionname);
create index linuxkernelnamecache_index on linuxkernelnamecache(varname);
create index functionname_c_index on functionnamecache_c(functionname);
create index varnamecache_c_index on varnamecache_c(varname);
create index functionname_java_index on functionnamecache_java(functionname);
create index fieldname_java_cache on fieldcache_java(fieldname);
create index classname_java_cache on classcache_java(classname);

create index stringidentifier_actionscript_index on stringscache_actionscript(stringidentifier);
create index scores_actionscript_index on scores_actionscript(stringidentifier);
create index package_actionscript_index on avgstringscache_actionscript(package);

create index stringidentifier_c_index on stringscache_c(stringidentifier);
create index scores_c_index on scores_c(stringidentifier);
create index package_c_index on avgstringscache_c(package);

create index stringidentifier_csharp_index on stringscache_csharp(stringidentifier);
create index scores_csharp_index on scores_csharp(stringidentifier);
create index package_csharp_index on avgstringscache_csharp(package);

create index stringidentifier_java_index on stringscache_java(stringidentifier);
create index scores_java_index on scores_java(stringidentifier);
create index package_java_index on avgstringscache_java(package);

create index stringidentifier_javascript_index on stringscache_javascript(stringidentifier);
create index scores_javascript_index on scores_javascript(stringidentifier);
create index package_javascript_index on avgstringscache_javascript(package);

create index stringidentifier_php_index on stringscache_php(stringidentifier);
create index scores_php_index on scores_php(stringidentifier);
create index package_php_index on avgstringscache_php(package);

create index stringidentifier_python_index on stringscache_python(stringidentifier);
create index scores_python_index on scores_python(stringidentifier);
create index package_python_index on avgstringscache_python(package);

create index stringidentifier_ruby_index on stringscache_ruby(stringidentifier);
create index scores_ruby_index on scores_ruby(stringidentifier);
create index package_ruby_index on avgstringscache_ruby(package);
