# ICM Selection List Manager

A tech demo for ICMInjector.ahk

## Parts:

* Main.ahk        - Opens browser window and interops with ICMInjector interface.
* Main.ico        - Icon for application (displayed directly from ahk).
* Main.html       - Structure for GUI
* Main.js         - Defines ruby functions, wraps ruby functions, calls these functions when certain HTML events are executed.
* Main.css        - Holds CSS for html to be displayed.

* ICMInjector.ahk - The engine which is capable of executing ruby scripts (pseudo-dynamically) with ICM.

# Design Preview

This is what the GUI will look like normally:

![closed](Docs\Closed.png)

When the lower right button is clicked the GUI will look like this:

![open](Docs\Open.png)

Here you will be able to select a selection list to perform operations on.

