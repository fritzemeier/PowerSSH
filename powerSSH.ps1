Param (
    
    [CmdletBinding()]

    [string[]]$target,
    [string]$ADuser,
    [switch]$AD,
    [string]$NETuser,
    [switch]$network = $false,
    [string[]]$cisco,
    [string[]]$aruba,
    [string[]]$fortinet,
    [switch]$c2 = $false,
    [switch]$help = $false,
    [switch]$list = $false,
    [switch]$retry = $false,
    [int]$timeout = 150,
    [switch]$passwd = $false,
    [switch]$report = $false,
    [securestring]$enable
    
)

Function Setup-SSH {

    if([string]::IsNullOrWhiteSpace(((Get-InstalledModule Posh-SSH) 2> $null))){

        $ans = Read-Host "`nPosh-SSH is required to run this script.`n | Enter [y] to install the module"
    
        if($ans -eq 'y'){
    
            # Initially attempts to install from known repos.
            try {

                Install-Module Posh-SSH

            } catch {

                # If the initial connection does not work, attempts to set up a temporarily-trusted repo 
                # within the working directory on the current host and install the package from there if available.

                Register-PSRepository PoshSSHInstallRepo -SourceLocation '.\' -InstallationPolicy Trusted

                $path_p = Get-ChildItem -Name posh*.nupkg
        
                # If the working directory does not have an installation package, attempt to pull one from the internet.

                if([string]::IsNullOrWhiteSpace($path_p) -and (Test-NetConnection -ComputerName "www.powershellgallery.com").PingSucceeded){
                    
                    Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/Posh-SSH/" -Path '.\posh.nupkg'
        
                    $path_p = Get-ChildItem -Name posh.nupkg
        
                } else {
        
                    Write-Host "`nNo Posh-SSH installation package found nor can one be pulled from a repo.`n | Please download and transfer one from https://www.powershellgallery.com/packages/Posh-SSH/ to this computer.`n"
                    exit
        
                }
        
                # Install the module and then remove the temporary repo.
                Install-Module -Name Posh-SSH

                Unregister-PSRepository PoshSSHInstallRepo

                $path_m = 'C:\Program Files\WindowsPowerShell\Modules\Posh-SSH\' + (Get-ChildItem 'C:\Program Files\WindowsPowerShell\Modules\Posh-SSH').Name + '\Posh-SSH.psd1'
                               
                Import-Module $path_m

            }

    
        } else {
        
            Write-Host "`nExiting Posh-SSH install.`n"
        
        }
    
    }

}

Function Sweep-Subnet {

    Param (

        [Parameter(Mandatory)]
        # [validatescript({
        #     if($_ -like '*/*'){

        #         $ip     = $_.split('/')[0]
        #         $bits   = $_.split('/')[1]
    
        #         (([System.Net.IPAddress]$ip).AddressFamily -eq 'InterNetwork')
    
        #         if(-not($bits)){
        #             throw 'CIDR notation missing.'
        #         } elseif (-not(0..32 -contains [int]$bits)){
        #             throw 'CIDR notation invalid.  Must be between 0 to 32.'
        #         }

        #     } elseif($_ -like '*-*') {

        #         if($_.split('.')[1] -like '*.*.*.*'){

        #             $min = $_.split('-')[0]
        #             $max = $_.split('-')[1]

        #         } else {

        #             $min = $_.split('-')[0]

        #             $max_base = $_.split('-')[0].split('.')[0..2] -join '.'
        #             $max = $max_base,$_.split('-')[1] -join '.'

        #         }

        #         (([System.Net.IPAddress]$min).AddressFamily -eq 'InterNetwork')
        #         (([System.Net.IPAddress]$max).AddressFamily -eq 'InterNetwork')


        #     } else {

        #         (([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork')

        #     }

        # })]
        [string]
        $range

    )

    Begin {

        $host_total = 0

         if($range -like '*/*'){

            [string]$cidr_addr  = $range.split('/')[0]
            [int]$cidr_bits     = $range.split('/')[1]

            $mask = ([math]::pow(2,$cidr_bits)-1) * [math]::pow(2,(32 - $cidr_bits))

            $bytes = [System.BitConverter]::GetBytes([Uint32] $mask)
            $subn_mask = (($bytes.Count - 1)..0 | ForEach-Object { [string] $bytes[$_] }) -join '.'
            $max_mask = ($subn_mask.split('.') | % { if($_ -eq '0'){return '255'}; return $_ }) -join '.'

            $ip_min = ([ipaddress](([ipaddress] $cidr_addr).Address -band ([ipaddress] $subn_mask).Address)).IPAddressToString

            $octet = [math]::floor($cidr_bits/8)
            $bit = (8-$cidr_bits % 8)

            $ctr_o = $octet

            $ip_max = ($ip_min.split('.')[0..($octet-1)]) -join '.'
            ($ip_min.split('.')[$octet..3]) | % {

                $oct_val = [int]::parse($_)

                if($ctr_o -eq $octet){

                    if($bit -ne 0){

                        $tmp_b = 0
                        $bits_added = 0
                        $exp = 0

                        while($exp -le $bit){

                            $bits_added = [math]::Pow(2,$exp) - 1
                            $exp++              

                        }

                    }

                    $ret_octet = $oct_val + $bits_added
                    $host_total += $bits_added


                }elseif($ctr_o -eq 3){
                    $host_total *= 254
                    $ret_octet = 254

                } else {

                    $host_total *= 255
                    $ret_octet = 255

                }

                $ip_max = $ip_max,$ret_octet -join '.'
                $ctr_o++
            
            }  

        } elseif($range -like '*-*'){

            if($range.split('-')[1] -match "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"){

                $ip_min = $range.split('-')[0]
                $ip_max = $range.split('-')[1]

                $start = $false

                0..3 | % {

                    $o = $_

                    $o
                    if($start){

                        $host_total += (254-[int]::parse($ip_min.split('.')[$o]))+[int]::parse($ip_max.split('.')[$o])
                    }

                    if([int]::parse($ip_max.split('.')[$o]) -ne [int]::parse($ip_min.split('.')[$o]) -and !$start -and $o -lt 3){

                        $start = $true
                        
                        $host_total = (([int]::parse($ip_max.split('.')[$o]) - [int]::parse($ip_min.split('.')[$o])) - 1) * [math]::Pow(254,(3-$o))

                    } elseif([int]::parse($ip_max.split('.')[$o]) -ne [int]::parse($ip_min.split('.')[$o]) -and $o -eq 3 -and !$start){

                        $host_total = [int]::parse($ip_max.split('.')[$o]) - [int]::parse($ip_min.split('.')[$o])

                    }

                }
                
            } else {

                $ip_min = $range.split('-')[0]

                $max_base = $range.split('-')[0].split('.')[0..2] -join '.'
                $ip_max = $max_base,$range.split('-')[1] -join '.'
    
                $host_total = [int]::Parse($ip_max.split('.')[3]) - [int]::Parse($ip_min.split('.')[3])

            }            

        } else {

            $ip_min = $range
            $ip_max = $range

        }

        $ip_curr = ''

        $ip_vals = $ip_min.split('.') | % { [int]::Parse($_) }

        $IP_hold = @()

        $host_counter = 0        

    }

    End {

        do {

            3..0 | % { 
                if($ip_vals[$_] -gt 0 -and $ip_vals[$_] % 255  -eq 0){

                    $ip_vals[$_ - 1]++
                    $ip_vals[$_] = 1

                } elseif($ip_vals[$_] -gt 0) {

                    $ip_curr = $ip_vals -join '.'

                }                

            }

            $IP_Hold += (new-object System.Net.Networkinformation.Ping).Send($($ip_curr),$timeout) | where-object {$_.Status -eq "success"} | select Address

            $ip_vals[$ip_vals.Count-1]++
            $host_counter++
            if($host_counter -le $host_total){
    
                Write-Progress -Activity "Testing hosts: $host_counter out of $host_total." -Status "$(($host_counter/$host_total)*100)%" -PercentComplete (($host_counter/$host_total)*100)
    
            } else {
    
                Write-Progress -Activity "Testing hosts: $host_counter out of $host_total." -Status "100%" -Completed
    
            }


        } while ($ip_curr -ne $ip_max)

        $IP_Hold


    }
    
}

Function Connect-SSH {

    Param (

        [Parameter(Mandatory)]
        [string]$addr,
        [Parameter(Mandatory)]
        [pscredential]$oldCreds,
        [array]$list
    )

    Begin {

        $cmd1 = "New-SSHSession $($addr) -Credential `$oldCreds -AcceptKey -Force 3> `$null"
        $cmd2 = "New-SSHSession $($addr) -Credential `$curr_c -AcceptKey -Force 3> `$null"
        $cmd3 = 'New-SSHSession $addr -Credential $($host.ui.PromptForCredential("Invalid credentials","Provided credentials were incorrect for $($addr).",$oldCreds.userName,"")) -AcceptKey -Force 3> $null'

        $err_msg = ''

    }

    End {

        
        # Attempt a login with the initial credentials provided.
        # Storing any error output helps to determine if a different method needs to be attempted.

        (Invoke-Expression $cmd1 -ErrorVariable err_msg -OutVariable ret_sess) 2> $null

        # If an error message is caught, use credential list if one is provided.
        if(![string]::IsNullOrWhiteSpace($list) -and ![string]::IsNullOrWhiteSpace($err_msg)){

            Write-Host "`nInitial credentials denied.`n | Attempting provided password list.`n"
         
            $list | % {

                $c = $_

                $curr_c = New-Object System.Management.Automation.PSCredential($c.UserName,$c.Password)


                if(![string]::IsNullOrWhiteSpace($err_msg)){

                    $err_msg = ''

                    (Invoke-Expression $cmd2 -ErrorVariable err_msg -OutVariable ret_sess) 2> $null

                }

            }

        }

        if(![string]::IsNullOrEmpty($err_msg)){ $err_msg | % { Write-Verbose $_ } }

        # If all credentials in password list fail, give user one more attempt by way of manual entry if so specified with the -retry flag.
        if(![string]::IsNullOrWhiteSpace($err_msg) -and $retry){
            $err_msg = ''

            
            (Invoke-Expression $cmd3 -ErrorVariable err_msg -OutVariable ret_sess) 2> $null

        } 
        

        if(![string]::IsNullOrEmpty($err_msg)){

            $err_msg | % { Write-Verbose $_ }

            Write-Host "Failed to connect to $($addr).`n`n"
            $err_msg | % { Write-Verbose $_ }

        }

        Start-Sleep -Seconds 1
        
    }

}

Function Check-ApplianceSSH {

    Param (

        [Parameter(Mandatory)]
        [system.io.stream]$SSHStream,
        [securestring]$sec

    )


    Begin {

        
        if(![string]::IsNullOrEmpty($sec)){
            
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            $enable_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        }

        $ret = ''

    }

    End {

        # Attempt different commands and check results for output which may suggest OS type.

        try {

            $SSHStream.WriteLine("enable"+[char]13+$enable_secret)
            Start-Sleep -Seconds 1        
            $output = $SSHStream.read()

            while($output -notlike "*#*"){

                $enable_t = Read-Host -AsSecureString "Enter 'enable' password" 

                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($enable_t)
                $enable_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    
                
                $SSHStream.WriteLine("enable"+[char]13+$enable_secret)
                Start-Sleep -Seconds 1        
                $output = $SSHStream.read()
    
            }

            $SSHStream.WriteLine( "show version")
            Start-Sleep -Seconds 1        
            $output = $SSHStream.read()

            switch($true){

                ($output -like "*ArubaOS*"){

                    $ret =  "Aruba"
        
                }
                ($output -like "*ArubaOS-CX*"){

                    $SSHStream.WriteLine("q")
                    Start-Sleep -Seconds 1        
                    $output += $SSHStream.read()
                    $ret =  "ArubaOSCX"

                }
                ($output -like "*Cisco*") {
                    $SSHStream.WriteLine("q")
                    Start-Sleep -Seconds 1        
                    $output += $SSHStream.read()
    
                    $ret = "Cisco"
    
                }

            }
    
            if(![string]::IsNullOrWhiteSpace($ret)){

                Write-Verbose $output
                return $ret

            }

            $SSHStream.WriteLine("get system status")
            Start-Sleep -Seconds 1        
            $output = $SSHStream.read()
    
            if($output -like "*Forti*"){

                $SSHStream.WriteLine("q")
                Start-Sleep -Seconds 1        
                $output = $SSHStream.read()
    
                return "Forti"
            
            }
    
            return "None"        

         } catch {}

    }


}

Function Gather-InformationSSH {

    Param (

        [Parameter(Mandatory)]
        [system.io.stream]$SSHStream,
        [Parameter(Mandatory)]
        [string]$appliance

    )

    Begin {

        $all_cmd = @{

            'aruba'=@('show version');
            'arubaoscx'='show version';
            'forti'=@('q','get system status','q');
            'cisco'=@('q','show version','q');

        }

        $dev_rep = @{

            # "All"=@();
            "Model"=$null;
            "Firmware"=$null;
            "Uptime"=$null;
            "Alerts"=$null;
            # "Recent"=$null;
            # "Critical"=$null;
        
        }


        
    }

    Process {}

    End {

        $rep_t = (Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds $all_cmd)

        $all = $rep_t.split("`n")

        switch($appliance){

            'Aruba'{

                # $dev_rep.all = (Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'aruba'='show version';}).split("`n")
                $dev_rep.model = ($all | Where-Object {$_ -like "*MODEL*"}).split("(").split(")")[1].split(" ")[1]
                $dev_rep.firmware = ($all | Where-Object {$_ -like "*MODEL*"}).split("(").split(")")[2].split(" ")[2]
                $dev_rep.uptime = (($all | Where-Object {$_ -like "*uptime*"}).replace("Switch uptime is ",""))
                $dev_rep.alerts = (Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'aruba'='show alarms'}).split("`n")[6-16]
                # $dev_rep.critical = (Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'aruba'='show alarms critical'})
                # $dev_rep.critical = (Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'aruba'='show alarms major | begin major'})
                

            }
            'Forti'{

                $dev_rep.model = (($all | Where-Object {$_ -like "Version:*"}).split(" ")[1])
                $dev_rep.firmware = (($all | Where-Object {$_ -like "Version:*"}).split(" ")[2])
                $dev_rep.uptime = (((Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'forti'='get system performance status | grep Uptime'}).split("`n") | Where-Object {$_ -like "Uptime: *"}).replace("Uptime: ",""))
                $dev_rep.alerts = ((Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'forti'='diagnose alertconsole list'}).split("`n")[2..12])

            }
            'Cisco'{

                $dev_rep.model = ($all[0].split(" ")[4..5] -join " ")
                $dev_rep.firmware = ($all[0].split(" ")[8])
                $dev_rep.uptime = (($all | Where-Object {$_ -like "*uptime*"}).split(" ")[3..8] -join " ")
                $dev_rep.alerts=((Execute-CommandSSH -stream $SSHStream -appliance $appliance -cmds @{'cisco'='show logging | begin Log Buffer'}).split("`n")[1..11])

            }


        }

        return $dev_rep

    }

}

Function Change-PasswordSSH {

    Param (
        
        [Parameter(Mandatory)]
        [system.io.stream]$stream,
        [Parameter(Mandatory)]
        [string]$appliance,
        [Parameter(Mandatory)]
        [string]$user,
        [Parameter(Mandatory)]
        [system.security.securestring]$newpass
        
    )

    Begin {

        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass)
        $newp = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        
        $output = ''

        if($appliance -eq 'Aruba'){

            $parse_user = (Execute-CommandSSH -stream $stream -cmds @{"aruba"="show running-config | include mgmt-user"} -appliance $appliance).split("`n")

            $role = (($parse_user | Where-object {$_ -like "mgmt-user*" -and $_ -like "*$($user)*"})).split(" ")[2]

        }

        $cmd_list = @{

            'aruba'=@("configure terminal mgmt-user $($user) $($role)",$newp,$newp);
            'arubaoscx'=@('conf',"user $($user) password",$newp,$newp,'end');
            'forti'=@("conf sys admin","ed admin",$newp,"set password $($newp)");
            'cisco'=@("enable",$enable_secret,"conf t","username $($user) privilege 15 secret $($newp)","end","copy running-config startup-config",[char]13)
            # if cisco enable secret not configured -- "enable secret $($newp)"
        }

    }

    End {

        try {
            
            # Depending on the appliace type, run a set of commands to change the password of the specified user.

            switch($appliance){

                'Forti'{
    
                    if($user -eq "admin"){
        
                        $output = (Execute-CommandSSH -stream $stream -cmds @{'forti'=@("conf sys admin","ed admin",$newp,"set password $($newp)")} -appliance $appliance)
        
                    } else {
    
                        $output = (Execute-CommandSSH -stream $stream -cmds @{'forti'=@("conf sys loc","ed $($user)","unset passwd","set passwd $($newp)")} -appliance $appliance)
                    
                    }

                    $stream.WriteLine("end")
                    Start-Sleep -Seconds 1
                    $output += $stream.read()

                }
                Default{ $output = (Execute-CommandSSH -stream $stream -cmds $cmd_list -appliance $appliance) }

            } 

            Write-Verbose $output

        } catch {}


    }

}

Function Execute-CommandSSH {

    Param (

        [Parameter(Mandatory)]
        [system.io.stream]$stream,
        [Parameter(Mandatory)]
        [object]$cmds,
        [Parameter(Mandatory)]
        [string]$appliance,
        [switch]$cnc = $false
    )

    Begin {

        $output = ''
        $shell_cmds = $false

    }

    End {

        if($cnc){ Write-Host "Host $($stream.session.connectioninfo.host)`n-----------------------------" }

        $cmds[$appliance] | % {

            $c_curr = $_


            $stream.WriteLine($c_curr)
            Start-Sleep -Seconds 1
            $output += $stream.read()  

        }

        if($cnc){ Write-Host "$($output)`n`n" }
        return $output

    }


}

Function C2 {

    Param (

        [Parameter(Mandatory)]
        [array]$connections

    )

    Begin {

        [boolean]$c2 = $true
        $collections = @{"Groups"=($groups = @{});"Targets"=($targets = @())}
    
        $cmd_keywords = @("group","groups","list","aruba","forti","cisco","sessions","rhosts","exit","clear","arubaoscx")
        $cmd_list = @{"Aruba"=@();"ArubaOSCX"=@();"Cisco"=@();"Forti"=@()}
        
        $skip = 0
    }

    End {

        # Run a loop to allow user to enter multiple commands.

        do {

            $cmd = $null
    
            Write-Host " $ > " -NoNewline
            $cmd = $host.ui.ReadLine()

            # Split entered command by spaces to parse what the user is entering.

            $running_cmd = $cmd.split(' ')
        
            $running_cmd | % { 

                # Specify the current keyword in the command.        
                $curr = $_

                # If a command is run that needs to use the next keyword, it will add to the $skip variable to avoid parsing the current $curr as a keyword.
                if($skip -gt 0){
                    $curr = ''
                    $skip--
                }

                # Switch case to determine what the user is attempting to run.
                switch($curr){
        
                    'target'{

                        # Allow user to specifiy a list of comma-delimited host IPs to execute against and then add them to the 'target' collection.
                        # i.e. 'rhosts 10.10.10.1,10.10.10.2'
                        
                        $r_t = $running_cmd[$running_cmd.IndexOf($curr)+1]

                        if($r_t -eq "all"){

                            $collections.targets = $connections.allinfo.stream

                        } elseif($r_t -like "range:*"){

                            $range = $r_t.split(':')[1]

                            $min = $range.split('-')[0]
                            $max = $range.split('-')[1]

                            $collections.targets = $connections.AllInfo.Stream[$connections.ByIP.Keys.IndexOf($min)..$connections.ByIP.Keys.IndexOf($max)]

                        } elseif($r_t -like "groups:*") {

                            $r_t = $r_t.split(":")[1]

                            try {

                                $r_t = $r_t.split(',')
    
                            } catch {}
    
                            $r_t | % {
    
                                $collections.Groups[$_] | % { 
    
                                        $sess = $_
    
                                        if($collections.targets.sessionid -notcontains $sess.sessionid){
    
                                            $collections.targets += $sess 
    
                                        }
                                
                                    }
    
                            }

                        } else {

                            try {

                                $r_t = $r_t.split(',')

                            } catch {

                                
                            }


                            $r_t | % {
    
                                $r_curr = $_

                                switch($true){

                                    ($collections.targets.session.connectioninfo.host -contains $r_curr -or $collections.targets.sessionid -contains $r_curr){ break }
                                    ($connections.BySessionId.Keys -Contains $r_curr){

                                        $collections.targets += ($connections.AllInfo | Where-Object -Property SessionId -eq $r_curr).stream

                                    }
                                    ($connections.ByIP.Keys -Contains $r_curr){

                                        $collections.targets += $connections.ByIP.$r_curr.stream
                                        

                                    }
                                    ($r_curr -eq 'aruba' -or $r_curr -eq 'cisco' -or $r_curr -eq 'forti'){

                                        $collections.targets += ($connections.AllInfo | Where-Object -Property Appliance -eq $r_curr).stream

                                    }

                                }
                                
                            }

                        }

                    }
                    'group'{

                        # Create a named group to keep together IPs if needed.
                        # i.e. 'group foo=10.10.10.1,10.10.10.2 bar=10.10.20.1,10.10.20.2'

                        $end = $false
                        $running_cmd[($running_cmd.indexof($curr)+1)..(($running_cmd.Count)-1)] | % {

                            $empty = @()
                            $g_t = @()
                            $g_name = ""
                            $g_hosts = @()

                            $g_c = $_

                            if($cmd_keywords -contains $g_c){

                                $end = $true
                            }

                            if(!$end){

                                # Switch case which determines if user specified a group name (i.e. foo=x.x.x.x), 
                                # otherwise use the current length of the groups list as the group name.
                                switch($true){

                                    Default{

                                        $g_name = $collections.Groups.Count
                                        $g_hosts = $g_c
                                        

                                    }
                                    ($g_c -like "*=*"){

                                        $g_name = $g_c.split("=")[0]
                                        $g_hosts = $g_c.split("=")[1]

                                        try {

                                            $g_hosts = $g_hosts.split(',')
                                        
                                        } catch {}

                                    }

                                }

                                # If the current group doesn't exists, create a new entry for it within the $collections.Groups hashtable.

                                if($collections.Groups.Keys -notcontains $g_name){

                                    $collections.Groups.Add($g_name,$empty)

                                }

                                # Loop through all indexes of entered IPs/SessionIds and add them to the group.
                                $g_hosts | % {

                                    $gh = $_

                                    switch($true){
                                        ($collections.Groups.$g_name.session.connectioninfo.host -contains $gh -or $collections.Groups.$g_name.sessionid -contains $gh){break}
                                        ($connections.ByIP.Keys -contains $gh){
                                            $collections.Groups.$g_name += $connections.ByIP.$gh.stream #   $connections.stream[$connections.IP.indexof($gh)]

                                        }
                                        ($connections.BySessionId.Keys -contains $gh){

                                            $collections.Groups.$g_name += ($connections.AllInfo | Where-Object -Property SessionId -eq $gh).stream

                                        }
                                        ($gh -eq 'aruba' -or $gh -eq 'cisco' -or $gh -eq 'forti'){

                                            $collections.Groups.$g_name += ($connections.AllInfo | Where-Object -Property Appliance -eq $gh).stream

                                        }
                                        Default{

                                            Write-Host "No matching sessions."

                                        }

                                    }

                                }

                            }

                        }

                    }
                    'clear'{
                     
                        # Clear a specified category.
                        # i.e.  'clear groups:foo'
                        #       'clear groups:*'
                        #       'clear targets'
                        $end = $false

                        # Loop to the end of the running command to parse all possible candidates to be cleared.
                        $running_cmd[($running_cmd.indexof($curr)+1)..($running_cmd.Count-1)] | % {

                            $cc = $_

                            # If a different command keyword is found, stop looking for any more candidates.
                            if($cmd_keywords -contains $cc){

                                $end = $true

                            }



                            if(!$end){

                                # Split the current candidate by ':' to determine category that is being cleared and what index of the category is being cleared.
                                $category = $cc.split(':')[0]
                                $v_rem = $cc.split(':')[1]

                                try {

                                    # Check to see if multiple things in one category are being specified in a comma-delimited list.
                                    $v_rem = $v_rem.split(',')

                                } catch {}

                                # For each of the items specified, parse them within their categories and nullify the memory they reside in.
                                $v_rem | % {

                                    $rem = $_

                                    switch($category){

                                        # Groups have the option to specify 'all', otherwise remove only one specific group.
                                        'groups'{ 
                                        
                                            if($rem -eq 'all'){

                                                $collections.$category = @{}

                                            } else {

                                                $collections.$category.Remove($rem) = $null  

                                            }
                                        
                                        }
                                        # Targets have the option to specify an IP address or the associated SessionId.  Otherwise the 'all' option will clear all targets.
                                        'targets'{ 


                                            switch($true){

                                                ($collections.targets.session.connectioninfo.host -contains $rem){ 

                                                    $r_arr = @()

                                                    $collections.targets | % {

                                                        $ct_curr = $_

                                                        if($ct_curr.session.connectioninfo.host -ne $rem){

                                                            $r_arr += $ct_curr 

                                                        }

                                                    }

                                                    $collections.targets = $r_arr

                                                    
                                                }
                                                ($collections.targets.sessionid -contains $rem){ 

                                                    # ($collections.targets.session.connectioninfo.host -contains $rem){ $collections.$category[$connections.ByIP.Keys.Index] = $null }

                                                    $r_arr = ($collections.targets | Where-Object -Property SessionId -ne $rem)
                                                                                                        
                                                    $collections.targets = $r_arr
                                                

                                                }
                                                ($rem -eq 'all'){ $collections.$category = @() }
                                                # Default { $collections.$category[$collections.$category.sessionid.indexof($rem)] = $null}

                                            }

                                        }

                                    }

                                }

                            }

                        }


                    }
                    # Specify client specific commands. Will also take a set of comma delimited commands/entries.
                    # i.e.  'aruba ping 10.10.10.1'
                    #       'forti get system status'
                    #       'cisco copy tftp: flash:,10.10.10.1,filename.txt,filename.txt,dir'
                    'aruba'{
        
                        $end = $false
                        $a_full = ""

                        # Loop over the current command and attempt to parse all keywords pertinent to the specified device.
                        $running_cmd[($running_cmd.indexof($curr)+1)..($running_cmd.Count-1)] | % {

                            $a_curr = $_

                            # If a different command keyword is found, stop parsing keywords for this device.
                            if($cmd_keywords -contains $a_curr){

                                $end = $true

                            }

                            # Add all pertinent keywords to the specified device's command list.
                            if(!$end){
                                
                                $skip++
                                $a_full += $a_curr + ' '

                            }

                        }

                        # Split the comma-delimited commands  into separate entries to be executed.
                        $cmd_list.Aruba = $a_full.split(',')

                    }
                    'arubaoscx'{
        
                        $end = $false
                        $a_full = ""

                        # Loop over the current command and attempt to parse all keywords pertinent to the specified device.
                        $running_cmd[($running_cmd.indexof($curr)+1)..($running_cmd.Count-1)] | % {

                            $a_curr = $_

                            # If a different command keyword is found, stop parsing keywords for this device.
                            if($cmd_keywords -contains $a_curr){

                                $end = $true

                            }

                            # Add all pertinent keywords to the specified device's command list.
                            if(!$end){
                                
                                $skip++
                                $a_full += $a_curr + ' '

                            }

                        }

                        # Split the comma-delimited commands  into separate entries to be executed.
                        $cmd_list.Aruba = $a_full.split(',')

                    }
                    'cisco'{

                        $end = $false
                        $c_full = ""

                        # Read over 'aruba' option for similar information on parsing 'cisco' commands.
                        $running_cmd[($running_cmd.indexof($curr)+1)..($running_cmd.Count-1)] | % {

                            $c_curr = $_

                            if($cmd_keywords -contains $c_curr){

                                $end = $true

                            }

                            if(!$end){

                                $c_full += $c_curr + ' '

                            }

                        }

                        $cmd_list.Cisco = $c_full.split(',')
                        
                    }
                    'forti'{

                        $end = $false
                        $f_full = ""
                        
                        # Read over 'aruba' option for similar information on parsing 'forti' commands.
                        $running_cmd[($running_cmd.indexof($curr)+1)..($running_cmd.Count-1)] | % {

                            $f_curr = $_

                            if($cmd_keywords -contains $f_curr){

                                $end = $true

                            }

                            if(!$end){

                                $f_full += $f_curr + ' '

                            }

                        }

                        $cmd_list.Forti = $f_full.split(',')

                    }
                    # List different categories. Multiple may be specified via comma-delimited list.
                    # i.e.  'list targets'
                    #       'list groups'
                    #       'list sessions'
                    #       'list commands,targets,groups,sessions'
                    'list'{

                        $skip++ 

                        # Store the keyword in the next index for parsing.
                        $l_n = $running_cmd[$running_cmd.indexof($curr)+1]


                        # Attempt to split up a comma-delimited list.
                        try {

                            $l_n = $l_n.split(',')

                        } catch {}

                        # Loop through all indexes of the specified categories to list and write them to the screen.
                        $l_n | % {

                            switch($_){

                                'sessions'{ 

                                    Write-Host "Connection List`n"

                                    $connections.AllInfo | % {

                                        "SessionId: $($_.SessionId)","IP: $($_.IP)","Type: $($_.Appliance)","`n" | % {

                                            Write-Host $_

                                        }

                                    }

                                    Write-Host "`n`n"


                                    # $connections | % {

                                    #     "SessionId: $($_.stream.sessionid)","IP: $($_.IP)","Type: $($_.Appliance)","`n" | % {
                                
                                    #         Write-Host $_

                                    #     }

                                    # }

                                }
                                'commands'{

                                    Write-Host "Command List`n"

                                    $cmd_list.Keys | % {

                                        Write-Host "$($_): $($cmd_list[$_] -join ',')"

                                    }

                                    Write-Host "`n`n" 
                                    
                                }
                                'groups'{

                                    Write-Host "Groups List`n"
                                    $collections.Groups.Keys | % {

                                        $key = $_
                                        $g_ips = @()
                                        $collections.Groups[$key].session.connectioninfo.host | % { $g_ips += $_ }



                                        "Group Name: $($key)","Hosts: $($g_ips -join ',')","`n" | % { 
                                        
                                            Write-Host $_ 
                                        
                                        }

                                    }

                                    Write-Host "`n`n" 

                                }
                                'targets'{

                                    Write-Host "Target List`n"

                                    $collections.targets.session.connectioninfo.host | % {

                                        Write-Host $_

                                    }

                                    Write-Host "`n`n" 

                                }

                            }

                        }

                    }
                    # Start a new PowerShell session within the C2. No current environment variables will carry over.
                    'shell'{

                        Write-Host " ! Dropping into new PowerShell session !`n"

                        Start-Process -Wait -NoNewWindow powershell.exe

                        Write-Host "`n`n ! Returning to powerSSH !`n"


                    }
                    # Run the specified commands against the specified targets.
                    'execute'{

                        $collections.targets | % {

                            $t_curr = $_

                            # Attempts to reconnect a session that may have been timed-out/disconnected for various reasons.
                            if(!$t_curr.session.isconnected){

                                Write-Host "Session disconnected, reconnecting...."

                                $t_arr = @()

                                $ec_out = (Invoke-SSHCommand 'show' -SessionId $t_curr.sessionid -EnsureConnection).output

                                # The use of separate arrays is due to an issue when a singular host/device is provided
                                # and indexing becomes problematic.

                                $connections.AllInfo.Stream[$connections.AllInfo.stream.sessionid.indexof($t_curr.sessionid)] = (New-SSHShellstream -SessionId $t_curr.sessionid)
                                $connections.BySessionId.$($t_curr.sessionid),$connections.ByIP.$($t_curr.session.connectioninfo.host) | % { $_ = $connections.AllInfo.Stream[$connections.AllInfo.stream.sessionid.indexof($t_curr.sessionid)] }

                                $collections.targets[$t_arr.indexof($t_curr.sessionid)] = (New-SSHShellstream -SessionId $t_curr.sessionid)

                                $t_arr += $collections.targets.sessionid

                                $t_curr = $collections.targets[$t_arr.indexof($t_curr.sessionid)]

                            }

                            Execute-CommandSSH -stream $t_curr -cmds $cmd_list -appliance $connections.ByIP.$($t_curr.session.connectioninfo.host).Appliance -cnc

                        }
                        
                    }
                    'exit'{
                        
                        $c2 = $false

                    }
        
                }
                
            }
        
        } while ($c2)

    }


}

Function Main {

    Begin {

        if($help){

            Write-Host "`nRemote password changer for Active Directory users and network devices. Also allows command execution on certain types of appliances.`n
            -target SUBNET/RANGE/LIST           Specify subnet range in CIDR notation, range of IPs, OR list of IPs separated by commas.
            -ADuser USERNAME                    Specify the AD user.
            -NETuser USERNAME                   Specify the network device user.
            -cisco/forti/aruba COMMAND          Specify which type of device commands should be executed upon.
            -list                               During script execution, a loop will run allowing user to create a list of credentials to test against the devices.`n"            
            exit

        }

        Write-Host "`n      PowerSSH`n--------------------`n"

        if(!$AD -and [string]::IsNullOrWhiteSpace($ADuser) -and !$network -and [string]::IsNullOrWhiteSpace($NETuser)){

        }

        if(!$network -and [string]::IsNullOrWhiteSpace($NETuser)){
            
        }

        Setup-SSH
                
        # Begin parsing the IPs specified by the user in CIDR notation, IP range, or individual hosts format.
        $ip_list = @()

        $target | % {
            (Sweep-Subnet -range $_) | % { 

                if($ip_list -notcontains $_.Address.IPAddressToString){

                    $ip_list += $_.Address.IPAddressToString

                }

            }
        
        }

        $conn_list = @()

        # If appliance specific commands are specified via the CLI arguments, place them in the hashtable.

        $arg_cmds = @{"Aruba"=$aruba;"Cisco"=$cisco;"Forti"=$fortinet}
        
    }
    
    End {

        if($AD -or [string]::IsNullOrWhiteSpace($ADuser)){

        }
        
        if($network -or ![string]::IsNullOrWhiteSpace($NETuser)){

            # Prompt for device login credentials as well as credentials to be changed

            $old_credentials = $host.ui.PromptForCredential("Current credentials","Enter current device login credentials.",$NETuser,"")

            if(!$passwd -and !$report){

                $ans = Read-Host "Do you wish to change device credentials? ( yes / [no] )"

                if($ans -eq 'yes'){

                    $passwd = $true

                }

            }

            if($passwd){

                $new_credentials = $host.ui.PromptForCredential("New credentials","---- NEW DEVICE CREDENTIALS ----",$old_credentials.userName,"")
                $verify_newcreds = $host.ui.PromptForCredential("New credentials","- Verify NEW DEVICE CREDENTIALS. -",$old_credentials.userName,"")

                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($new_credentials.Password)
                $new_c = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($verify_newcreds.Password)
                $verify_newc = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

                while($new_c -ne $verify_newc){

                    $new_credentials = $host.ui.PromptForCredential("New credentials","!!!! PASSWORDS DID NOT MATCH !!!!",$old_credentials.userName,"")
                    $verify_newcreds = $host.ui.PromptForCredential("New credentials","! Verify NEW DEVICE CREDENTIALS. !",$old_credentials.userName,"")
    
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($new_credentials.Password)
                    $new_c = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($verify_newcreds.Password)
                    $verify_newc = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

                }

            }

            if([string]::IsNullOrEmpty($enable)){
                Write-Host "`n"
                $enable = Read-Host -AsSecureString "Enter 'enable' password" 
                if([string]::IsNullOrEmpty($enable)){ Write-Host "Leaving 'enable' password empty." }

            }

            # If the '-list' flag is specified, prompt user for multiple credentials until the username specified is 'exit'. Users run the risk of having SSH time them out using this option.
            if($list){

                $list_arr = @()

                $list_creds = $old_credentials

                while(($list_creds.UserName).ToLower() -ne 'exit'){

                    ($list_creds = $host.ui.PromptForCredential("Creating credential list","Enter multiple credentials for list. Set username as 'exit' to escape the loop.",$NETuser,"")) *> $null

                    if(($list_creds.UserName).ToLower() -ne 'exit'){

                        $list_arr += $list_creds

                    }

                }

            }

            # Using each of the IPs that were found available, begin attempting to connect to them via SSH and then store the necessary info into the 'conn_list' array.
            Write-Host "`n`n"
            $ip_list | ForEach-Object { 

                if(![string]::IsNullOrEmpty($_)) { 

                    Write-Host "Connecting to $($_)" 
                    $str_sess = (Connect-SSH -addr $_ -oldCreds $old_credentials -list $list_arr) 2> $null
                
                    # Attempt to connect to the device and begin an SSH shell stream.
                    $shstr_cmd = "New-SSHShellStream -SessionId `$str_sess.sessionid" 
                    $stream = (Invoke-Expression $shstr_cmd -ErrorVariable shstr_errmsg) 2> $null

                    # Run appliance-specific commands to identify what the OS of the device may be.
                    if([string]::IsNullOrEmpty($shstr_errmsg)){
                        $appliance = Check-ApplianceSSH -SSHStream $stream -sec $enable

                        # Store the connection info.
                        $init_info = New-Object psobject -Property @{

                            "IP" = $_
                            "Appliance" = $appliance
                            "Stream" = $stream
                            "SessionId" = $stream.sessionid

                        }
                        
                        $conn_info = New-Object PSObject -Property @{

                            "ByIP" = @{$_=$init_info}
                            "BySessionId" = @{$stream.sessionid=$init_info}
                            "AllInfo" = $init_info


                        }
                        
                        $conn_list += $conn_info              

                        if($report){ 
                            
                            $dev_report = (Gather-InformationSSH -SSHStream $stream -appliance $appliance)
                            
                            $dev_report.Keys | % { $key = $_; Write-Host " | $($key): $($dev_report.$key)"}

                        }

                        if(![string]::IsNullOrWhiteSpace($new_credentials.UserName)){

                            # If the user provided credentials for a password change, run the ChangePassword function.

                            Change-PasswordSSH -stream $stream -appliance $appliance -user $new_credentials.userName -newpass $new_credentials.password

                            $cmd = "(New-SSHSession `$_ -Credential `$new_credentials -AcceptKey -Force) 2> `$null"

                            (Invoke-Command $cmd -OutVariable check_sess -ErrorVariable err_var -WarningVariable warn_var) *> $null

                            # $check_sess = (New-SSHSession $_ -Credential $new_credentials -AcceptKey -Force) 2> $null    

                            if([string]::IsNullOrEmpty($check_sess)){

                                Write-Host " | Password change failed."

                            } else {

                                Write-Host " | Password change successful."
                                Remove-SSHSession -SessionId $check_sess.sessionid 2>&1> $null

                            }
                    
                        }       

                        if(![string]::IsNullOrWhiteSpace($arg_cmds[$appliance])){

                            # If the type of appliance has commands that were specified via the CLI, run said commands.

                            Execute-CommandSSH -stream $stream -cmds $arg_cmds -appliance $appliance -cnc

                        }

                        Write-Host "`n`n"

                        # " | Appliance type: $($appliance)"," | Stream SessionId: $($stream.sessionid)","`n`n" | % { Write-Host $_ }

                    } else {

                        $shstr_errmsg | % { Write-Verbose $_ } 

                    }


                }

            }

            # If specified, begin running C2 functionality.

            if($c2 -and ![string]::IsNullOrEmpty($conn_list)){

                C2 -connections $conn_list               

            }

            # Clean up all sessions opened by the script.

            if(![string]::IsNullOrEmpty($conn_list.AllInfo.IP)){ $conn_list.AllInfo.stream.sessionid | % { Remove-SSHSession -Index $_ 2>&1> $null } }

        }

    }

}


Main