from tkinter import*


def popup(event ):
	pmenu.tk_popup(event.x_root,event.y_root)

def app():
	messagebox.showinfo("About the app","Version 1.0 \nMade in Kz")
def author():
	messagebox.showinfo("About the author","Version 1.0 \nMade in Kz ")

def close ():
	if messagebox.askyesno("Exit , Do you really  want  to go out ? ")
       wn.destroy()
def newfile():
	wn.title("Untitled.txt")
	pole.delte(1.0  ,END) # It will delte  all text ,  when you create  new  file 


def openfile (event=None):
filename=filedialog.askopenfilename()
pos=filename.rfind("/")+
newName = filename[pos:]

file=open(filename"r")#read
content=file.read()
pole.insert(1.0,content)
file.close()
wn.title(newName)


def savefile(event=None):
	filename=filedialog.askopenfilename()
	file=open(filename"w")#write
content=pole.get(1.0,END)
file.write(content)
file.close()

def cut(event=None):
	pole.event_generate("<<Cut>>")# It's  ready  function  of  Cut 

def copy(event=None):
	pole.event_generate("<<Copy>>")# It's  ready  function  of  Copy 

def paste(event=None):
	pole.event_generate("<<Paste>>")# It's  ready  function  of  Paste 	





wn=Tk()
wn.geometry("700x700")
wn.title("SkyNotepad 1.0")

menubar = Menu()
wn.config(menu=menubar)

fmenu = Menu(menubar)
menubar.add_cascade(label="File",menu=fmenu)

fmenu.add_command(label= "New file",accelerator = "Ctrl+N", command=newfile)
fmenu.add_command(label="Open",accelerator="Ctrl+O",command=openfile)
fmenu.add_command(label="Save",accelerator="Ctrl+S",command=savefile)
fmenu.add_command(label="Close", accelerator="Ctrl+W",command=closefile)



aboutmenu = Menu(menubar)
menubar.add_cascade(label="About",menu=aboutmenu)

aboutmenu.add_command(label="About the app",command=app)
aboutmenu.add_command(label="About author",command=author)

panel=Frame(wn)
panel.pack()

nfb=Button (image = nfi,command=newfile)
nfb=grid(row=0,column=1)

ofb=Button (image = ofi,command=openfile)
ofb=grid(row=0,column=2)

sfb=Button (image = sfi,command=savefile)
sfb=grid(row=0,column=3)

ub=Button()
ub=grid(row=0,column=4)


pole = Text (wn,undo=True)
pole.pack()


pmenu=Menu(pole)
pmenu.add_command(label="cut",command=cut)
pmenu.add_command(label="copy",command=paste)
pmenu.add_command(label="paste",command=paste)
pole.bind("<Button-2>",popup)
wn.protocol("WM_DELTE_WINDOW",close ) # If  user  wil want go out 
pole.bind("<Control-n >", newfile) 
pole.bind("<Control-o>", openfile) 
pole.bind("<Control-s >", savefile) 



