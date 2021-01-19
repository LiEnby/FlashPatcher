In Adobe Flash Player versions newer than 32.0.0.344 they added a "Timebomb" for the EOL.
the player would refuse to run any custom flash content after 12/01/2021,

So knowing this, Lets crack it!


I acturally started looking into this before the 12/01/2021 hit, 
but only recently did i acturally discover a way to bypass the killswitch

# Location
First thing i wanted to know was, so where does flash install to anyway? its a browser plugin right, 
so its not like theres an obvious "Flash.exe" or whatever,

Well it was as simple as googling the answer, this just applies to windows systems but its in
C:\Windows\System32\Macromed\Flash (32 bit version in SysWOW64)
there are three files it uses for different browsers and apis, the NPAPI Firefox one is NPSWF64.DLL, 
the Chromium verison is PepFlashPlayer_<VERSION>.dll and the activeX version for Internet Explorer and desktop apps is Flash.OCX, 

Oh and google is special and have it in %LocalAppData%\Google\Chrome\User Data\PepperFlash\<VERSION>\Pepflashplayer.dll

# Identification
There were a few ways i thought it might work but one thing about the kill screen is that it still said "Adobe Flash Player 32"
when i right clicked, and had the option for global settings and local settings this made me think that the killscreen really is just
a SWF (Flash Movie) file itself, that it'll load instead of whatever is on the site, knowing this i did a very basic search looking
for "CWS" the flash movie magic number inside the DLL, 
