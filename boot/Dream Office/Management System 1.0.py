from tkinter import* 
from tkinter import messagebox

import sqlite3
root=Tk()

root.geometry("900x500")
root.title("Scool Management")

con=sqlite3.connect('StudentManage.db')
cur=con.cursor()

def Stu_database():
	name=e1.get()    #  " get()"  input  from keyboard 
	RollNo=e2.get()
	Age=e3.get()
	Gender=var.get()
	Email=e4.get()
	p=en1.get()
	c=en2.get()
	m=en3.get()
	tot=int(en1.get())+int(en2.get())+int(en3.get())

	cur.execute('CREATE TABLE IF NOT EXISTS StudentData (Name TEXT,RollNo TEXT,Age TEXT , Gender TEXT , Email TEXT ,Physics TEXT ,Chemistry TEXT ,Math TEXT , Total TEXT)')
	cur.execute('INSERT INTO StudentData (Name,RollNo , Age , Gender , Email , Physics, Chemistry ,Math.Total) values(?, ?, ? , ? , ? , ?,?,?, ?) '  ,(name, RollNo, Age, Gender, Email, p,c,m,tot ,))
	con.commit()

	e1.delete(0,END)
	e2.delete(0,END)
	e3.delete(0,END)
	e4.delete(0,END)
	en1.delete(0,END)
	en2.delete(0,END)

def Read_stu_data():
	cur.execute("SELECT * FROM StudentData")
	data=cur.fetchall()
	m=1
	for i in data:
		print(f"{m}.")
		print(f"name->{i[0]}")
		print(f"RollNo->{i[1]}")
		print(f"Age->{i[2]}")
		print(f"Gender->{i[3]}")
		print(f"Email->{i[4]}")
		print(f"Physics->{i[5]}")
		print(f"Chemistry->{i[6]}")
		print(f"Math->{i[7]}")
		print(f"Total->{i[8]}")
		print("___________________")
		m+=1

def Search_Stu():

	cur.execute("SELECT * FROM StudentData")
	data=cur.fetchall()
	m=1
	for i in data: 
		if entryStu.get() == i[0]:
                             print(f"{m}. ")
		print(f"name->{i[0]} ")
		print(f"RollNo->{i[1]} ")
		print(f"Age->{i[2]}")
		print(f"Gender->{i[3]}")
		print(f"Email->{i[4]}" )
		print(f"Physics->{i[5]}")
		print(f"Chemistry->{i[6]}")
		print(f"math->{i[7]} ")
		print("Total->{i[8]}" )
		print("___________________")

		break

                             
		  
	              
	else:
		messagebox.showinfo("Error404" , "Data not Found")

conn=sqlite3.connect('FaculManage.db')
curso=conn.cursor()

#function of  faculty in Data Base 

def Facul_database():

	name=e1.get()
	occupation=e2.get()
	Age=e3.get()
	Gender=var.get()
	Email=e4.get()

	curso.execute('CREATE TABLE IF NOT EXISTS FacultyData (Name TEXT , Occupation TEXT, Age TEXT , Gender TEXT , Email TEXT)')
        curso.execute('INSERT INTO FacultyData(Name , Occupation , Age , Gender , Email) vaules(?,?,?,?,?)' , (name,occupation, Age,Gender, Email,))

	conn.commit()


	e1.delete(0,END)
	e2.delete(0,END)
    e3.delete(0,END)
    e4.delete(0,END)

def Read_facul_data():

	curso.execute("SELECT * FROM FacultyData") # execute is  " do  or  perfomance "
	data=curso.fetchall()
	m=1
	for i in data:
		    print(f"{m}.")
		    print(f"name->{i[0]}")
		    print(f"RollNo->{i[1]}")
		    print(f"Age->{i[2]}")
		    print(f"Gender->{i[3]}")
		    print(f"Email->{i[4]}")
		    print("________________________")
		    m+=1


def Search_Facul():
	curso.execute("SELECT *FROM FacultyData")
	data=curso.fetchall()
	m=1
	for i in data :
		if entryFacul.get() == i[0]:
			print(f"{m}.")
			print(f"name->{i[0]}")
		    print(f"RollNo->{i[1]}")
		    print(f"Age->{i[2]}")
		    print(f"Gender->{i[3]}")
		    print(f"Email->{i[4]}")
		    print("________________________")

		    break
		m+=1
	else:


		   messagebox.showinfo("Error404", "Data not Found ")

def Add_stu_data():
	screen1=Toplevel(root)
	screen1.geometry("900x500")
	screen1.resizable(0,0)
	screen1.title("Student Registration")
	global e1, e2 , e3, var , e4 

	Label(screen1,text="Student Profile" , font=("arial" ,25), fg="green").pack()

	label=Label(screen1,text="Student Name :", font=("arial", 15), fg="yellow", bg="gray").place(x=40, y=60)

	e1 = Entry(screen1 ,withd=25 ,font=("calibri" , 15))
	e1.place(x=230 , y=65)


	Label(screen1,text="Student RollNo:", font("arial", 15), fg="yellow", bg="gray").place(x=40, x=120)


	e2=Entry(screen1,width=25 , font=("calibri",15))
    e2.place(x=230,y=130)


    Label(screen1, text="Student Age:" , font=("arial", 15), fg="yellow" , bg="gray").place(x = 40 , y =180)

    e3=Entry(screen1 , width=25 ,font=("calibrity", 15))
    e3.place(x=230 ,y=190)


    Label(scren1,text="Gender:" , font=("arial",15), fg="yellow" , bg="blue").place(x=40,y=240)

    var=StringVar()

    Radiobutton(screen1,text="Male" , variable= var ,vaule='male',font=("arial",12) , fg="red").place(x=210,y=240)
    Radiobutton(screen1,text="Female" , variable= var ,vaule='female',font=("arial",12) , fg="red").place(x=300,y=240)

    Label(screen1 ,text="Email :" ,font=("arial",15),fg="yellow",bg="gray").place(x=40, y=300)

    e4=Entry(screen1,width=25 , font=("calibri",15))
    e4.place(x=230 , y=305)

    Label(screen1 ,text="Marks in PCM :" , font=("calibri",15), fg="yellow" ,bg="gray").place(x=40,y=360)

    Label(screen1,text="Physics" , font("calibri" ,15) , fg="yellow", bg="green").place(x=40 ,y=400)
    global en1
    en1=Entry(screen1,width=6,font=("calibri",15))
    en1.place(x=110,y=400)


    Label(screen1, text="Chemistry", font=("calibri",15) , fg="yellow" , bg="gray").place(x=180 ,y=400)
    global en2
    en2=Entry(screen1 ,width=6 , font=("calibri"))
    en2.place(x=275,y=400)

    Label(screen1, text="Math" , font=("calibri", 15) , fg="yellow" , bg="green").place(x=345 , y=400)
    global en3
    en3=Entry(screen1,width=6,font=("calibri",15))
    en3.place(x=400 ,y=400)

global x,en4

def Total_no():
	x=IntVar()


    	en4=Entry(screen1,width=20,font=("calibri",15),textvariable=x)
    	en4.place(x=90 ,y=400)

    	t=str(int(en1.get())+int(en2.get())+int(en3.get()) )
    	x.set(t)

Button(screen1, text="Total" , font=("calibri" , 13), bg="yellow" ,fg="gray" , command=Total_no).place(x=40 ,y=430 )



    	
Button(screen1, text="Add Data" , font=("calibri" , 13), bg="yellow" ,fg="gray" , command=Total_no).place(x=40 ,y=430 )



def Add_facul_data():
	screen1=Toplevel(root)
	screen1.geometry("900x500")
	screen1.resizable(0,0)
	screen1.title("Faculty Registration")
	global e1 , e2 ,e3 ,e4 , var 

	Label(screen1 ,text= "Faculty Profile" , font=("arial", 25), fg="green").pack()

	label=Label(screen,text="Faculty Name :" ,  font=("arial", 15), fg="yellow" , bg="gray").place(x=40 , y=60) 


    e1=Entry(screen1 ,width=25 ,font=("calibri" , 15))
    e1.place(x=230,y=65)

    Label(screen1,text="Faculty Occupation: " , font=("arial" , 15), fg="yellow" , bg="gray").place(x=40 ,y=120)

    e2=Entry(screen1 ,width=25 ,font=("calibri", 15))
    e2.place(x=230 , y=130)

    Label(screen1,text="Faculty Age :" , font = ("arial" ,15),fg="yellow" ,bg="blue").place(x=40 ,y=180)

    e3=Entry(screen1,width=25,font=("calibri",15))
    e3.place(x=230,y=190)

    Label(screen1,text="Gender:",font=("arial",15),fg ="yellow" , bg="blue").place(x=40 , y=240)

    var=StringVar()

    #Compare previos function 

    Radiobutton(screen1 ,text= "Male" ,variable=var , vaule='male' , font=("arial",12),fg="red").place(x=210 , y=240)
    
    Radiobutton(screen1 ,text= "Female" ,variable=var , vaule='female' , font=("arial",12),fg="red").place(x=300 , y=240)

    Label(screen1 ,text ="Email : " , font=("arial" ,15), fg="yellow", bg="blue").place(x=40,y=300)


    e4=Entry(screen1 ,width=25 , font=("calibri" ,15))
    e4.place(x=230 , t=305)


    |Button(screen1 , text="Add Data" , font=("calibri", 13), bg= "yellow" , fg="blue" , command=Facul_database).place(x= 180  ,y= 350)



def Search_stu_data():
	screen3=Toplevel(root)
	screen3.geometry("900x500")
	screen3.resizable(0,0)
	screen3.title("Searching")

	Label(screen3, text="Search Student " , font=("arial", 25), fg="green").pack()

	Label(screen3, text="Enter Name to Search" , font =("arial" ,15) , fg="yellow" ,bg= "blue").place(x=90, y=80)
	global entryStu
	entryStu=Entry(screen3, withd=25 ,font=("calibri", 13))
	entryStu.place(x=75, y=120)


	Button(screen3, text="Search" ,font=("calibri",13),fg="blue", bg="yellow", command=Search_Stu).place(x=149, y=150)


def Search_facul_data():
	screen3=Toplevel(root)
	screen3.geometry("900x500")
	screen3.resizable(0,0)
	screen3.title("Searching")

	LabeL(screen3,text="Search Faculty" , font=("arial" ,25), fg="green").pack()

	Label(screen3,text="Enter Name to Search" ,font=("arial" , 12), fg="yellow" , bg="blue").place(x=90 , y=80)
	global entryFacul
	entryFacul=Entry(screen3 ,width=25 ,font=("calibri" , 13))
	entryFacul.place(x=75,y=120)


	Button(screen3 , text="Search" , font=("calibri",13), fg="blue" , bg="yellow" , command=Search_Facul).place(x=149 , y=150)



label=Label(root,text="Scool Management System" ,font=("arial" , 25) , bg="blue" , fg="yellow")
label.pack()

Button (root , text= "Add Student Data" ,font=("Arial" ,15) ,command=Add_stu_data).place(x=40,y=60)

Button(root, text="Search Student Data" ,font=("Arial", 15), command=Search_stu_data).place(x=40, y=120)



Button(root, text="Show Student Data" ,font=("Arial", 15), command=Read_stu_data).place(x=40, y=180)

Button(root, text="Add Faculty Data" ,font=("Arial", 15), command=Add_facul_data).place(x=290, y=60)
		
Button(root, text="Search_facul_data" ,font=("Arial", 15), command=Search_facul_data).place(x=290, y=180)
	

Button(root, text="Show Faculty Data" ,font=("Arial", 15), command=Read_facul_data).place(x=290, y=120)


root.mainloop()
