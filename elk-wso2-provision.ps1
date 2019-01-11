$ELK_VERSION = "6.5.4"
$ELK_ENV = "c:\tools2"


# Download ELK stack
mkdir -Force $ELK_ENV\logs | Out-Null
Invoke-WebRequest "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-oss-$ELK_VERSION.zip"				-OutFile "$ELK_ENV\elasticsearch-oss-$ELK_VERSION.zip"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/kibana/kibana-oss-$ELK_VERSION-windows-x86_64.zip"			-OutFile "$ELK_ENV\kibana-oss-$ELK_VERSION-windows-x86_64.zip"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/logstash/logstash-oss-$ELK_VERSION.zip"						-OutFile "$ELK_ENV\logstash-oss-$ELK_VERSION.zip"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-$ELK_VERSION-windows-x86_64.zip"	-OutFile "$ELK_ENV\filebeat-oss-$ELK_VERSION-windows-x86_64.zip"


# Unzip ELK stack
Expand-Archive -Path "$ELK_ENV\elasticsearch-oss-$ELK_VERSION.zip"				-DestinationPath "$ELK_ENV"
Expand-Archive -Path "$ELK_ENV\kibana-oss-$ELK_VERSION-windows-x86_64.zip"		-DestinationPath "$ELK_ENV"
Expand-Archive -Path "$ELK_ENV\logstash-oss-$ELK_VERSION.zip"					-DestinationPath "$ELK_ENV"
Expand-Archive -Path "$ELK_ENV\filebeat-oss-$ELK_VERSION-windows-x86_64.zip"	-DestinationPath "$ELK_ENV"


# Delete .zips
Remove-Item –path "$ELK_ENV\*" -include *oss*


# Create Logstash configuration file
$logstash_config = @"
input
{
	beats {
		type => "beats"
		host => "0.0.0.0"
		port => 5044
	}
}

filter
{
	grok {
		match => { "message" => [
								'\ATID: %{GREEDYDATA:tenant_id} %{GREEDYDATA:server_type} \[%{TIMESTAMP_ISO8601:timestamp}\]%{SPACE}%{LOGLEVEL:log_level} \{%{GREEDYDATA:log_originator}\}%{SPACE}-%{SPACE}%{GREEDYDATA:log_message}',
								'\ATID: %{GREEDYDATA:tenant_id} %{GREEDYDATA:server_type} \[%{TIMESTAMP_ISO8601:timestamp}\] %{SPACE}%{LOGLEVEL:log_level} \{%{JAVACLASS:log_originator}\}%{SPACE}-%{SPACE}%{GREEDYDATA:log_message}'
								]}
	}

	mutate {
		add_field => { "read_timestamp" => "%{@timestamp}" }
	}

	date {
    	match => [ "timestamp" , "ISO8601" ]
  	}
	
	mutate {
		remove_field => [ "timestamp" , "message" ]
	}
}

output
{
	stdout {
		codec => dots
	}

	elasticsearch {
		hosts => ["localhost:9200"]
		index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
	}
}
"@
[System.IO.File]::WriteAllText("$ELK_ENV\logstash-$ELK_VERSION\config\logstash-main.conf", $logstash_config)


# Create Filebeat configuration file
$filebeat_config = @"
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - $ELK_ENV\logs\*

  multiline.pattern: '^TID: \[-?\d*\] \[\w*\] \[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(,\d+)?\] '
  multiline.negate: true
  multiline.match: after

filebeat.config.modules:
  path: .\modules.d\*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 3

setup.kibana:
  host: "localhost:5601"

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
"@
[System.IO.File]::WriteAllText("$ELK_ENV\filebeat-$ELK_VERSION-windows-x86_64\filebeat-main.yml", $filebeat_config)


# Create shortcuts for ELK stack
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Elasticsearch.lnk")
$Shortcut.TargetPath = "$ELK_ENV\elasticsearch-$ELK_VERSION\bin\elasticsearch.bat"
$Shortcut.Save()

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Kibana.lnk")
$Shortcut.TargetPath = "$ELK_ENV\kibana-$ELK_VERSION-windows-x86_64\bin\kibana.bat"
$Shortcut.Save()

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Logstash.lnk")
$Shortcut.TargetPath = "$ELK_ENV\logstash-$ELK_VERSION\bin\logstash.bat"
$Shortcut.Arguments = " -f $ELK_ENV\logstash-$ELK_VERSION\config\logstash-main.conf"
$Shortcut.Save()

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Filebeat.lnk")
$Shortcut.TargetPath = "$ELK_ENV\filebeat-$ELK_VERSION-windows-x86_64\filebeat.exe"
$Shortcut.Arguments = " -c $ELK_ENV\filebeat-$ELK_VERSION-windows-x86_64\filebeat-main.yml"
$Shortcut.Save()