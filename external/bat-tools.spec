Summary: A collection of extra tools for the Binary Analysis Tool
Name: bat-extratools
Version: 1.0
Release: 1
License: GPLv2+
Source: %{name}-%{version}.tar.gz
Group: Development/Tools
Packager: Armijn Hemel <armijn@binaryanalysis.org>

%description
A collection of extra tools for the Binary Analysis Tool, scraped from GPL source code releases and firmware replacement projects.

%prep
%setup -q
%build
make
