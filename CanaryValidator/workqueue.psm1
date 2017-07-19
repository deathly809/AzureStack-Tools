
# Locks
$Global:mutex = New-Object System.Threading.Mutex
$Global:countMutex = New-Object System.Threading.Mutex

# "Name" -> { "DependsOnMe" , }
$Global:Dependendents = [hashtable]::Synchronized(@{})

# "Name" -> { "I depend on" , }
$Global:DependsOn = [hashtable]::Synchronized( @{} )

# list of jobs to run when dependencies met
$Global:Jobs = [hashtable]::Synchronized(@{})

# Scheduled to run
$Global:Scheduled = [System.Collections.ArrayList]::Synchronized($())

# Currently running
$Global:Running = [System.Collections.ArrayList]::Synchronized($())

# Finished running
$Global:Finished = [System.Collections.ArrayList]::Synchronized($())

$Global:QueueRunning = $false

$runspace = [runspacefactory]::CreateRunspace()
$runspace.Open()

# Jobs added
$runspace.SessionStateProxy.SetVariable('Jobs', $Global:Jobs)

# Job queues
$runspace.SessionStateProxy.SetVariable('Scheduled', $Global:Scheduled)
$runspace.SessionStateProxy.SetVariable('Running', $Global:Running)
$runspace.SessionStateProxy.SetVariable('Finished', $Global:Finished)

# Queue state
$runspace.SessionStateProxy.SetVariable('QueueRunning', $Global:QueueRunning)

<#
.SYNOPSIS
Lock the mutex is available.

.DESCRIPTION
Lock the mutex is available, if not availble the caller is blocked until the lock has been released.

.PARAMETER Mutex
The parameter to lock.

.EXAMPLE
Enter-Lock -Mutex $MyMutex

.NOTES
General notes
#>
function Enter-Lock {
    param(
        [ValidateNotNullOrEmpty()]
        [System.Threading.Mutex]$Mutex = $Global:mutex
    )
    $Mutex.WaitOne() | Out-Null
}

function Exit-lock {
    param(
        [ValidateNotNullOrEmpty()]
        [System.Threading.Mutex]$Mutex = $Global:mutex
    )
    $Mutex.ReleaseMutex() | Out-Null
}


function Add-Job {
    param(
        [Parameter(Required = $true)]
        [string]$Name,

        [Parameter(Required = $true)]
        [ScriptBlock]$Job,

        [Parameter()]
        [System.Collections.ObjectModel.Collection``1[string]]$DependsOn = {}.Invoke()
    )

    $vars = Get-Variable -Scope 1

    Enter-Lock
    $Global:DependsOn.Add($Name, $DependsOn)
    foreach ($deps in $DependsOn) {
        $arr = $Global:Dependendents.Get($deps)
        if (-not $arr) {
            $arr = {$Name}.Invoke()
        }
        else {
            $arr.Add($Name)
        }
        $Global:Dependendents.Add($deps, $arr)
    }

    $Global:Scheduled.Add($Name)
    $Global:Jobs.Add($Name, $Script)
    Exit-Lock
    
}


function Invoke-Job {
    param(
        [System.Management.Automation.PSCustomObject]$Job
    )

    # Job is composed of 
    #   Name - Name of the job
    #   Script - The job contents
    #   Arguments - The list of arguments
    

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()

    $runspace.SessionStateProxy.SetVariable("Name", $Job.Name)
    $runspace.SessionStateProxy.SetVariable("Script", $Job.Script)
    $runspace.SessionStateProxy.SetVariable("Arguments", $Job.Arguments)

    $runspace.SessionStateProxy.SetVariable("Scheduled", $Global:Scheduled)
    $runspace.SessionStateProxy.SetVariable("Running", $Global:Running)
    $runspace.SessionStateProxy.SetVariable("Finished", $Global:Finished)

    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace
    $powershell.AddScript( {
            $Scheduled.Remove($Job.Name)
            $Running.Add($Job.Name)
            Invoke-Command -ScriptBlock $Job.Script -ArgumentList $Arguments
            $Running.Remove($Name)
            $Finished.Add($Name)
        }) | Out-Null
    $powershell.BeginInvoke()
}

<#
.SYNOPSIS
Start the work queue

.DESCRIPTION
Runs a background job which will monitor the work queues for jobs.  Once a job 
has been placed in the scheduled queue we remove it and begin executing it and 
then move it to the running queue.

.PARAMETER PollTime
Determines how often to poll the queues, in milliseconds.

.EXAMPLE
Start-Queue

.NOTES
General notes
#>
function Start-WorkQueue {
    param(
        [Parameter()]
        [int]$PollTime = 100
    )

    if ($Global:QueueRunning) {
        return
    }

    Enter-Lock
    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace
    $powershell.AddScript(
        {
            Write-Output "Running queue"
            while ($QueueRunning) {

                # Run scheduled jobs
                foreach ($job in $Scheduled) {
                    Invoke-Job $Jobs[$job]
                }

                Enter-Lock
                foreach ($done in $Finished) {

                    # remove dependency
                    $child = $Dependents[$done]
                    $deps = $Dependencies[$child]
                    $deps.Remove($done)
                    $Dependencies[$child] = $deps
                    
                    # schedule to run
                    if ($deps.Count -eq 0) {
                        $Scheduled.Add($child)
                    }

                    # remove job from list of all jobs in queue
                    $Jobs.Remove($done)
                }
                $Finished.Clear()

                Exit-lock
            }
            Write-Output "Stopping Queue"
        }
    )
    Exit-Lock
}