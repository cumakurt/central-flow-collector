Name:           flowcollector
Version:        4.0.0
Release:        1%{?dist}
Summary:        Central Flow Collector & Flow Analytics Platform
License:        AGPL-3.0-only
URL:            https://github.com/cumakurt/central-flow-collector
Packager:       Cuma KURT <cumakurt@gmail.com>
BuildArch:      x86_64
Source0:        flowcollector-linux-amd64
Source1:        config.example.yaml
Source2:        flowcollector.service
Source3:        LICENSE
Source4:        NOTICE

%description
High-performance NetFlow v5/v9, IPFIX and sFlow collector with flow analytics.

%install
mkdir -p %{buildroot}/usr/local/bin %{buildroot}/etc/flowcollector %{buildroot}/usr/lib/systemd/system
install -m 0755 %{SOURCE0} %{buildroot}/usr/local/bin/flowcollector
install -m 0640 %{SOURCE1} %{buildroot}/etc/flowcollector/config.yaml
install -m 0644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/flowcollector.service
mkdir -p %{buildroot}%{_datadir}/licenses/%{name}
install -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -m 0644 %{SOURCE4} %{buildroot}%{_datadir}/licenses/%{name}/NOTICE

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%license %{_datadir}/licenses/%{name}/NOTICE
/usr/local/bin/flowcollector
%config(noreplace) /etc/flowcollector/config.yaml
/usr/lib/systemd/system/flowcollector.service
