# FI Gate 1 build - Windows Server 2019 exact acceptance configuration
# This package is intentionally pinned to the reviewed Gate 1 build artifacts
# and the current FI repository checkpoint. No GitHub/repository writes occur.

$FI2019 = [ordered]@{
    ControllerHost        = 'AdminBox'
    TargetHost            = 'ISS-FS-19'
    ExpectedBuild         = '17763'
    ExpectedRepoCommit    = 'c5157b255f1d33cc0fd33ca1ddb0708348728912'

    RepoRoot              = 'C:\Users\jwood.admin\src\fi'
    GovernedRoot          = 'C:\FI-Governed-Test'
    CollectorAccount      = 'ISS\gFI-FS19$'
    HelperAccount         = 'ISS\gFI-USN-FS19$'

    LocalCollector        = 'C:\FI-Test\fi-gate1-collector.exe'
    CollectorSHA256       = '6D641A73D0CE116BA09C16885371164BF580D36631DD6F031090B2EE5DC86C13'
    LocalHelper           = 'C:\FI-Test\fi-gate1-usn.exe'
    HelperSHA256          = 'A71A769F25E9CCB0C9ACAF8CAFBE6C751AEB8F3884FC5EBD1BF7723B3BBF2263'

    RemoteWorkRoot        = 'C:\FI-Test\FI-Gate1-Server2019'
    RemoteCollector       = 'C:\FI-Test\FI-Gate1-Server2019\fi-gate1-collector.exe'
    RemoteHelper          = 'C:\FI-Test\FI-Gate1-Server2019\fi-gate1-usn.exe'
    RemoteToolsRoot       = 'C:\FI-Test\FI-Gate1-Server2019\tools'
    RemoteResultDirectory = 'C:\ProgramData\FI\gate1-results'

    LocalResultDirectory  = 'C:\FI-Test\FI-Gate1-Server2019-Results'
}
