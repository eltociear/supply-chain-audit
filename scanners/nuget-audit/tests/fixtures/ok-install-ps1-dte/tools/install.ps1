param($installPath, $toolsPath, $package, $project)
# Mark the config file as copy-always
$item = $project.ProjectItems.Item("app.config.transform")
$item.Properties.Item("CopyToOutputDirectory").Value = 1
$dte.ItemOperations.Navigate("https://github.com/example/readme")
