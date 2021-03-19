$Root = [ADSI]"LDAP://RootDSE"
$rootdn = $Root.rootDomainNamingContext

$scp = New-Object System.DirectoryServices.DirectoryEntry;

$scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $rootdn;

$scp.Keywords;
