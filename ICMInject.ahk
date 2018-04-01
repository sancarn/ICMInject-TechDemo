Global CONST_RUBY_INJECTOR_TEXT := "DEV: RubyScript Inject"
Global DEFAULT_FILE             := "injector.rb"
Global WM_COMMAND               := 0x111


class Injector {
	static modes      := {}
    static scripts    := {}
    static addonAddrs := {}
	static addonPaths := {}
	static callbacks  := {}
	
	static activePIDs := {}
	static disabledPIDs := {}
	
	;If install is default then overwrite file, else assume custom. Do not overwrite file.
	;If not installed correctly, install and ask for restart
	
	__makeInjector(path=0){
		if path = 0
			path = %A_Appdata%\Innovyze\WorkgroupClient\scripts\injector.rb
		
		rb = 
		(
			require 'win32ole'

			class Sandbox
			  def Sandbox.new()
				return binding
			  end
			end

			invoker = WIN32OLE.connect("{5c172d3c-c8bf-47b0-80a4-a455420a6911}")
			code = invoker.scripts[$$]
			mode = invoker.modes[$$]


			invoker.rbActive($$,[mode,code])
			  begin
				case mode 
				  when 0
					data = Sandbox.new.eval(code,__FILE__,__LINE__)
				  when 1
					data = eval(code,binding,__FILE__,__LINE__)
				  else
					box = "box" + mode.to_s
					$boxes ||= {}
					$boxes[box] ||= Sandbox.new
					data = $boxes[box].eval(code,__FILE__,__LINE__)
				end
			  rescue Exception => e
				data = ["ERROR",e]
			  end
			invoker.rbClosing($$,data)
		)
	}
	
	__requestRestart(PID){
		if winexist("ahk_exe InnovyzeWC.exe")
		{
			Msgbox, ICM Requires a restart. Do you want to restart ICM now?
			if ErrorLevel {
				Msgbox, ICM will restart shortly
				WinClose, ahk_exe InnovyzeWC.exe
				RunWait, InnovyzeWC.exe /ICM
			} else {
				this.disabledPIDs[PID] := True
			}
		}
	}
	
	;3 Possible cases:
	;	Case 1. User does not have a scripts.csv
	;		-> Install scripts.csv -> Ask for ICM to restart -> return 0
	;	Case 2. User has a scripts.csv, however scripts.csv does not contain Inject RubyScript key.
	;		-> Append line to scripts.csv -> Ask for ICM to restart -> return 0
	;	Case 3. User has a scripts.csv AND scripts.csv contains Inject RubyScript key.
	;		-> return 1 (can execute)
	__checkInstall(PID){
		;Define Ruby Path
		rbPath = %A_Appdata%\Innovyze\WorkgroupClient\scripts\injector.rb
		scriptsPath = %A_Appdata%\Innovyze\WorkgroupClient\scripts\scripts.csv
		
		;Check if already disabled
		if this.disabledPIDs[PID] {
			this.__requestRestart()
			return 0
		}
		
		;If addon has already been evaluated jump straight to execution
		;Note each instance of ICM may have it's own address for ICMInject.rb
		;for this reason we store that data in a dictionary object 'addonAddrs'.
		if (!this.addonAddrs[PID]){
			;Does scripts.csv exist?
			if fileexist(scriptsPath){	;if scripts.csv exists
				;Case 2 & 3
				Loop, read, %scriptsPath% 
				{
					index := A_Index + 1
					data := A_LoopReadLine
					
					If instr(data,CONST_RUBY_INJECTOR_TEXT){
						;Case 3
						;Index has been found
						m1 := StrSplit(data,",")[2]
						this.addonAddrs[PID] := index -1
						this.addonPaths[PID] := m1
						if this.addonPaths[PID] = "injector.rb" 
							this.__makeInjector()
						return 1
					}
				}
				
				;Case 2
				;If we get here then scripts.csv must not contain injector.rb
				;So let's add it, ask for a restart and return 0
				sContent := CONST_RUBY_INJECTOR_TEXT . "," . DEFAULT_FILE
				FileAppend,%sContent% , %scriptsPath%
				
				;Create injector script
				this.__makeInjector()
				this.__requestRestart(PID)
				return 0
			} else {
				;Case 1
				FileCreateDir, %scriptsPath%
				sContent := CONST_RUBY_INJECTOR_TEXT . "," . DEFAULT_FILE
				FileAppend, %sContent%, %scriptsPath%
				this.__makeInjector()
				this.__requestRestart(PID)
				return 0
			}
		} else {
			if this.addonPaths[PID] = "injector.rb"
				this.__makeInjector()
			return 1
		}
	}
	
	__callAddon(id,pid){
		;ID = 1:  35080
		;ID = 2:  35081
		;ID = 3:  35082
		; ...
		
		WinGet, hwnd, id, ahk_pid %pid%
		
		wParam := 35080 + id - 1
		PostMessage, %WM_COMMAND%,%wParam%,0,,ahk_id %hwnd%
		
	}
	
	execute(rb,mode:=0,PID:=0,protectedRequest:=1){
		;If PID == 0, use most recent PID
		if PID=0
			WinGet, PID, PID, ahk_exe InnovyzeWC.exe
		
		if !this.__checkInstall(PID)
			return 0
		
		;If PID is active already, return -1
		if this.activePIDs[PID]
			return -1
		
		;protectedRequest is recommended. Using forced requests will likely cause crashes.
		;if protected request is true, see if icm has a network tab using MSAA. If it doesn't return error -2
		if protectedRequest
			if !this.hasNetworkTab(PID)
				return -2
		
		;Setup Interop parameters for given process
		this.scripts[PID] := rb
		this.modes[PID]   := mode
		
		
		this.__callAddon(this.addonAddrs[PID],PID)
		
		return 1
	}
	
	hasNetworkTab(PID){
		;TODO: <-- Use MSAA to determine whether ICM given by the specified PID has a network tab.
		return true
	}
	
	getError(id){
		if id=0
			return "Error: [Execute:#" id "] Not installed correctly. Please restart."
		else if id=-1
			return "Error: [Execute:#" id "] ICM is already active at this time."
		else if id=-2
			return "Error: [Execute:#" id "] ICM is not able to run ruby scripts at this time."
		
	}
	
	executeFile(file,mode:=0,PID:=0){
		ruby=load('%file%')
		return this.execute(ruby,mode,PID)
	}
	
	;Event -  Active
	rbActive(pid,data=0){
		this.activePIDs[pid] := 1
		if this.callbacks[pid]
			this.callbacks[pid].call("running",data)
	}
	
	;Event - Closing
	rbClosing(pid,data=0){
		this.activePIDs[pid] := 0
		if this.callbacks[pid]
			this.callbacks[pid].call("closing",data)
	}
}




;$t = WIN32OLE.connect("{5c172d3c-c8bf-47b0-80a4-a455420a6911}")
;$t.scripts[$$]
ObjRegisterActive(Injector,"{5c172d3c-c8bf-47b0-80a4-a455420a6911}")

if result=1
	TrayTip, ICMInject, The ruby script injected successfully., 0.1, 16+1
else
	TrayTip, ICMInject, The ruby script was not injected., 0.05, 16+1
sleep,3000
HideTrayTip()


#Persistent
OnExit Revoke
return

Revoke:
; This "revokes" the object, preventing any new clients from connecting
; to it, but doesn't disconnect any clients that are already connected.
; In practice, it's quite unnecessary to do this on exit.
	ObjRegisterActive(Injector, "")
	ExitApp
return


^+e::
	reload
return





HideTrayTip() {
    TrayTip  ; Attempt to hide it the normal way.
    if SubStr(A_OSVersion,1,3) = "10." {
        Menu Tray, NoIcon
        Sleep 200  ; It may be necessary to adjust this sleep.
        Menu Tray, Icon
    }
}

;May consider registering this interface under a name, e.g. 
;https://msdn.microsoft.com/en-us/library/windows/desktop/ms678477(v=vs.85).aspx
;	ProgID := "InfoWorks.Injector"
;	CLSID  := "{5c172d3c-c8bf-47b0-80a4-a455420a6911}"
;	file_extension := "icmj" ;?



/*
	https://autohotkey.com/boards/viewtopic.php?f=6&t=6148
    ObjRegisterActive(Object, CLSID, Flags:=0)
    
        Registers an object as the active object for a given class ID.
        Requires AutoHotkey v1.1.17+; may crash earlier versions.
    
    Object:
            Any AutoHotkey object.
    CLSID:
            A GUID or ProgID of your own making.
            Pass an empty string to revoke (unregister) the object.
    Flags:
            One of the following values:
              0 (ACTIVEOBJECT_STRONG)
              1 (ACTIVEOBJECT_WEAK)
            Defaults to 0.
    
    Related:
        http://goo.gl/KJS4Dp - RegisterActiveObject
        http://goo.gl/no6XAS - ProgID
        http://goo.gl/obfmDc - CreateGUID()
*/
ObjRegisterActive(Object, CLSID, Flags:=0) {
    static cookieJar := {}
    if (!CLSID) {
        if (cookie := cookieJar.Remove(Object)) != ""
            DllCall("oleaut32\RevokeActiveObject", "uint", cookie, "ptr", 0)
        return
    }
    if cookieJar[Object]
        throw Exception("Object is already registered", -1)
    VarSetCapacity(_clsid, 16, 0)
    if (hr := DllCall("ole32\CLSIDFromString", "wstr", CLSID, "ptr", &_clsid)) < 0
        throw Exception("Invalid CLSID", -1, CLSID)
    hr := DllCall("oleaut32\RegisterActiveObject"
        , "ptr", &Object, "ptr", &_clsid, "uint", Flags, "uint*", cookie
        , "uint")
    if hr < 0
        throw Exception(format("Error 0x{:x}", hr), -1)
    cookieJar[Object] := cookie
}