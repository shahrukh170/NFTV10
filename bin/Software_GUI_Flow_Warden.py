#!/usr/bin/python3
# The code for changing pages was derived from: http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/	
import sys
sys.path.append('../src/')
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.pyplot import figure
from pylab import *
import threading
#from matplotlib import style
#style.use('ggplot')
import matplotlib
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg ##, NavigationToolbar2Tk
try:
    from matplotlib.backends.backend_tkagg import NavigationToolbar2TkAgg
except ImportError:
    from matplotlib.backends.backend_tkagg import NavigationToolbar2TkAgg as NavigationToolbar2TkAgg
#from matplotlib.backends.backend_tkagg import ( FigureCanvas2TkAgg, NavigationToolbar2TkAgg)
from matplotlib.figure import Figure
import numpy as np 
import sys,time
import Tkinter
from Tkinter import *
from tkinter.ttk import *
from Tkinter import *
from tkinter import scrolledtext
try:
   from tkinter import *
   import tkinter as tk
   import tkinter as ttk
except ImportError:
    import Tkinter as ttk
    
if sys.version_info[0] < 3:
    import Tkinter as Tk
else:
    import tkinter as Tk
    from tkinter import messagebox 
    import tkinter as tk
    from tkinter import ttk
from cores.cli import cliArgumentsToConfiguration
from cores.stores import NetflowsStore, RulesStore
from cores.baseclass import NetflowMeter, FlowbasedFilter
frame_styles = {"relief": "groove",
                "bd": 3, "bg": "blue",
                "fg": "red", "font": ("Arial", 9, "bold")}

frame_stylesx = {"relief": "groove",
                "bd": 3, "bg": "blue",
                "fg": "green", "font": ("Arial", 9, "bold")}
LARGE_FONT= ("Verdana", 12)
grid_labels = []
##fig = plt.figure(figsize=(8, 6))
#fig,([ax1,ax2],[ax3,ax4]) =  plt.subplots(2,2,figsize=(10,4))
fig,[ax1,ax2] =  plt.subplots(1,2,figsize=(9.35,2.75))
fig1,[ax3,ax4] =  plt.subplots(1,2,figsize=(9.35,2.75))

# You can also use a pandas dataframe for pokemon_info.
# you can convert the dataframe using df.to_numpy.tolist()
pokemon_info = [['Bulbasaur', 'Grass', '318'], ['Ivysaur', 'Grass', '405'], ['Venusaur', 'Grass', '525'], ['Charmander', 'Fire', '309'], ['Charmeleon', 'Fire', '405'], ['Charizard', 'Fire', '534'], ['Squirtle', 'Water', '314'], ['Wartortle', 'Water', '405'], ['Blastoise', 'Water', '530'], ['Caterpie', 'Bug', '195'], ['Metapod', 'Bug', '205'], ['Butterfree', 'Bug', '395'], ['Weedle', 'Bug', '195'], ['Kakuna', 'Bug', '205'], ['Beedrill', 'Bug', '395'], ['Pidgey', 'Normal', '251'], ['Pidgeotto', 'Normal', '349'], ['Pidgeot', 'Normal', '479'], ['Rattata', 'Normal', '253'], ['Raticate', 'Normal', '413'], ['Spearow', 'Normal', '262'], ['Fearow', 'Normal', '442'], ['Ekans', 'Poison', '288'], ['Arbok', 'Poison', '448'], ['Pikachu', 'Electric', '320'], ['Raichu', 'Electric', '485'], ['Sandshrew', 'Ground', '300'], ['Sandslash', 'Ground', '450'], ['Nidoran?', 'Poison', '275'], ['Nidorina', 'Poison', '365'], ['Nidoqueen', 'Poison', '505'], ['Nidoran?', 'Poison', '273'], ['Nidorino', 'Poison', '365'], ['Nidoking', 'Poison', '505'], ['Clefairy', 'Fairy', '323'], ['Clefable', 'Fairy', '483'], ['Vulpix', 'Fire', '299'], ['Ninetales', 'Fire', '505'], ['Jigglypuff', 'Normal', '270'], ['Wigglytuff', 'Normal', '435'], ['Zubat', 'Poison', '245'], ['Golbat', 'Poison', '455'], ['Oddish', 'Grass', '320'], ['Gloom', 'Grass', '395'], ['Vileplume', 'Grass', '490'], ['Paras', 'Bug', '285'], ['Parasect', 'Bug', '405'], ['Venonat', 'Bug', '305'], ['Venomoth', 'Bug', '450'], ['Diglett', 'Ground', '265'], ['Dugtrio', 'Ground', '425'], ['Meowth', 'Normal', '290'], ['Persian', 'Normal', '440'], ['Psyduck', 'Water', '320'], ['Golduck', 'Water', '500'], ['Mankey', 'Fighting', '305'], ['Primeape', 'Fighting', '455'], ['Growlithe', 'Fire', '350'], ['Arcanine', 'Fire', '555'], ['Poliwag', 'Water', '300'], ['Poliwhirl', 'Water', '385'], ['Poliwrath', 'Water', '510'], ['Abra', 'Psychic', '310'], ['Kadabra', 'Psychic', '400'], ['Alakazam', 'Psychic', '500'], ['Machop', 'Fighting', '305'], ['Machoke', 'Fighting', '405'], ['Machamp', 'Fighting', '505'], ['Bellsprout', 'Grass', '300'], ['Weepinbell', 'Grass', '390'], ['Victreebel', 'Grass', '490'], ['Tentacool', 'Water', '335'], ['Tentacruel', 'Water', '515'], ['Geodude', 'Rock', '300'], ['Graveler', 'Rock', '390'], ['Golem', 'Rock', '495'], ['Ponyta', 'Fire', '410'], ['Rapidash', 'Fire', '500'], ['Slowpoke', 'Water', '315'], ['Slowbro', 'Water', '490'], ['Magnemite', 'Electric', '325'], ['Magneton', 'Electric', '465'], ["Farfetch'd", 'Normal', '377'], ['Doduo', 'Normal', '310'], ['Dodrio', 'Normal', '470'], ['Seel', 'Water', '325'], ['Dewgong', 'Water', '475'], ['Grimer', 'Poison', '325'], ['Muk', 'Poison', '500'], ['Shellder', 'Water', '305'], ['Cloyster', 'Water', '525'], ['Gastly', 'Ghost', '310'], ['Haunter', 'Ghost', '405'], ['Gengar', 'Ghost', '500'], ['Onix', 'Rock', '385'], ['Drowzee', 'Psychic', '328'], ['Hypno', 'Psychic', '483'], ['Krabby', 'Water', '325'], ['Kingler', 'Water', '475'], ['Voltorb', 'Electric', '330'], ['Electrode', 'Electric', '490'], ['Exeggcute', 'Grass', '325'], ['Exeggutor', 'Grass', '530'], ['Cubone', 'Ground', '320'], ['Marowak', 'Ground', '425'], ['Hitmonlee', 'Fighting', '455'], ['Hitmonchan', 'Fighting', '455'], ['Lickitung', 'Normal', '385'], ['Koffing', 'Poison', '340'], ['Weezing', 'Poison', '490'], ['Rhyhorn', 'Ground', '345'], ['Rhydon', 'Ground', '485'], ['Chansey', 'Normal', '450'], ['Tangela', 'Grass', '435'], ['Kangaskhan', 'Normal', '490'], ['Horsea', 'Water', '295'], ['Seadra', 'Water', '440'], ['Goldeen', 'Water', '320'], ['Seaking', 'Water', '450'], ['Staryu', 'Water', '340'], ['Starmie', 'Water', '520'], ['Scyther', 'Bug', '500'], ['Jynx', 'Ice', '455'], ['Electabuzz', 'Electric', '490'], ['Magmar', 'Fire', '495'], ['Pinsir', 'Bug', '500'], ['Tauros', 'Normal', '490'], ['Magikarp', 'Water', '200'], ['Gyarados', 'Water', '540'], ['Lapras', 'Water', '535'], ['Ditto', 'Normal', '288'], ['Eevee', 'Normal', '325'], ['Vaporeon', 'Water', '525'], ['Jolteon', 'Electric', '525'], ['Flareon', 'Fire', '525'], ['Porygon', 'Normal', '395'], ['Omanyte', 'Rock', '355'], ['Omastar', 'Rock', '495'], ['Kabuto', 'Rock', '355'], ['Kabutops', 'Rock', '495'], ['Aerodactyl', 'Rock', '515'], ['Snorlax', 'Normal', '540'], ['Articuno', 'Ice', '580'], ['Zapdos', 'Electric', '580'], ['Moltres', 'Fire', '580'], ['Dratini', 'Dragon', '300'], ['Dragonair', 'Dragon', '420'], ['Dragonite', 'Dragon', '600'], ['Mewtwo', 'Psychic', '680'], ['Mew', 'Psychic', '600']]


LARGE_FONT= ("Verdana", 12)
class MenuBar(tk.Menu):
    def __init__(self, parent):
        tk.Menu.__init__(self, parent)

        menu_file = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Menu1", menu=menu_file)
        menu_file.add_command(label="All Widgets", command=lambda: parent.show_frame(Some_Widgets))
        menu_file.add_separator()
        menu_file.add_command(label="Exit Application", command=lambda: parent.Quit_application())

        menu_orders = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Menu2", menu=menu_orders)

        menu_pricing = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Menu3", menu=menu_pricing)
        menu_pricing.add_command(label="Page One", command=lambda: parent.show_frame(PageOne))

        menu_operations = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Menu4", menu=menu_operations)
        menu_operations.add_command(label="Page Two", command=lambda: parent.show_frame(PageTwo))
        menu_positions = tk.Menu(menu_operations, tearoff=0)
        menu_operations.add_cascade(label="Menu5", menu=menu_positions)
        menu_positions.add_command(label="Page Three", command=lambda: parent.show_frame(PageThree))
        menu_positions.add_command(label="Page Four", command=lambda: parent.show_frame(PageFour))

        menu_help = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Menu6", menu=menu_help)
        menu_help.add_command(label="Open New Window", command=lambda: parent.OpenNewWindow())


class GUI(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.main_frame = tk.Frame(self,  height=600, width=1024) ###bg="#BEB2A7",
        # self.main_frame.pack_propagate(0)
        self.main_frame.pack(fill="both", expand="true")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
class FlowWardenProject(tk.Tk):

    def __init__(self, *args, **kwargs):
        
        tk.Tk.__init__(self, *args, **kwargs)

        #tk.Tk.iconbitmap(self, default="clienticon.ico")
        tk.Tk.wm_title(self, "Ms-Engineering-Thesis-Software")
        
        
        container = tk.Frame(self, bg="#84CEEB", height=600, width=400)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.data = []
        
        try:
            self.ChildObject= PageOne(container,self,object)
            self.data = self.ChildObject.get_Props()
            self.ChildObject.set_Stored_Data(self.data)
            ##print(self.ChildObject.get_Stored_Data())
           
            
            
        except Exception as e:
            #print('Failed Error : '+ str(e))
            pass    
        self.frames = {}
        pages = ( PageOne, PageTwo, PageThree, PageFour,Some_Widgets)
        for F in pages:
            frame = F(container, self,self.data)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")
            
        
        #self.show_frame(Some_Widgets)
        self.show_frame(PageOne)
        #self.show_frame(PageThree)    
        menubar = MenuBar(self)
        tk.Tk.config(self, menu=menubar)

    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()
        
    def OpenNewWindow(self):
        OpenNewWindow()

    def Quit_application(self):
        self.destroy()

        
class Some_Widgets(GUI):  # inherits from the GUI class
    def __init__(self, parent, controller,object):
        GUI.__init__(self, parent)

        frame1 = tk.LabelFrame(self, frame_styles, text="This is a LabelFrame containing a Treeview")
        frame1.place(rely=0.05, relx=0.02, height=400, width=400)

        frame2 = tk.LabelFrame(self, frame_styles, text="Some widgets")
        frame2.place(rely=0.05, relx=0.45, height=500, width=500)

        button1 = tk.Button(frame2, text="tk button", command=lambda: Refresh_data())
        button1.pack()
        button2 = ttk.Button(frame2, text="ttk button", command=lambda: Refresh_data())
        button2.pack()

        Var1 = tk.IntVar()
        Var2 = tk.IntVar()
        Cbutton1 = tk.Checkbutton(frame2, text="tk CheckButton1", variable=Var1, onvalue=1, offvalue=0)
        Cbutton1.pack()
        Cbutton2 = tk.Checkbutton(frame2, text="tk CheckButton2", variable=Var2, onvalue=1, offvalue=0)
        Cbutton2.pack()

        Cbutton3 = ttk.Checkbutton(frame2, text="ttk CheckButton1", variable=Var1, onvalue=1, offvalue=0)
        Cbutton3.pack()
        Cbutton3 = ttk.Checkbutton(frame2, text="ttk CheckButton2", variable=Var2, onvalue=1, offvalue=0)
        Cbutton3.pack()

        Lbox1 = tk.Listbox(frame2, selectmode="multiple")
        Lbox1.insert(1, "This is a tk ListBox")
        Lbox1.insert(2, "Github")
        Lbox1.insert(3, "Python")
        Lbox1.insert(3, "StackOverflow")
        Lbox1.pack(side="left")

        Var3 = tk.IntVar()
        R1 = tk.Radiobutton(frame2, text="tk Radiobutton1", variable=Var3, value=1)
        R1.pack()
        R2 = tk.Radiobutton(frame2, text="tk Radiobutton2", variable=Var3, value=2)
        R2.pack()
        R3 = tk.Radiobutton(frame2, text="tk Radiobutton3", variable=Var3, value=3)
        R3.pack()

        R4 = tk.Radiobutton(frame2, text="ttk Radiobutton1", variable=Var3, value=1)
        R4.pack()
        R5 = tk.Radiobutton(frame2, text="ttk Radiobutton2", variable=Var3, value=2)
        R5.pack()
        R6 = tk.Radiobutton(frame2, text="ttk Radiobutton3", variable=Var3, value=3)
        R6.pack()

        # This is a treeview.
        tv1 = Treeview(frame1)
        column_list_account = ["Name", "Type", "Base Stat Total"]
        tv1['columns'] = column_list_account
        tv1["show"] = "headings"  # removes empty column
        for column in column_list_account:
            tv1.heading(column, text=column)
            tv1.column(column, width=50)
        tv1.place(relheight=1, relwidth=0.995)
        treescroll = tk.Scrollbar(frame1)
        treescroll.configure(command=tv1.yview)
        tv1.configure(yscrollcommand=treescroll.set)
        treescroll.pack(side="right", fill="y")

        def Load_data():
            for row in pokemon_info:
                tv1.insert("", "end", values=row)

        def Refresh_data():
            # Deletes the data in the current treeview and reinserts it.
            tv1.delete(*tv1.get_children())  # *=splat operator
            Load_data()

        Load_data()


class PageOne(GUI):
    def __init__(self, parent, controller,object):
        GUI.__init__(self, parent)
        self.colour = StringVar()
        self.colour.set('white')  
        self.label = tk.Label(self.main_frame, font=("Verdana", 20), bg=self.colour.get(),text="NETFLOW WARDEN Version : 1.0")
        self.label.pack(side="top")
        self.container=self
        self.controller =controller
        self.data = []
        # getting screen's height in pixels 
        height = controller.winfo_screenheight() 
  
        # getting screen's width in pixels 
        width = controller.winfo_screenwidth()
        
        #Data
        group = Tkinter.LabelFrame(self.main_frame, text="Data", padx=130, pady=20)
        group.place(x=10, y=100)

        frame1 = tk.Frame(group) ##, bg="#84CEEB")
        frame2 = tk.Frame(group) ##, bg="#84CEEB")
        frame3 = tk.Frame(group) ##, bg="#84CEEB")
        frame4 = tk.Frame(group) ##, bg="#84CEEB")
        frame5 = tk.Frame(group) ##, bg="#84CEEB")
        frame6 = tk.Frame(group) ##, bg="#84CEEB")
        frame7 = tk.Frame(group) ##, bg="#84CEEB")
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)
        frame4.pack(side=tk.TOP)
        frame5.pack(side=tk.TOP)
        frame6.pack(side=tk.TOP)
        frame7.pack(side=tk.TOP)
               

        Tkinter.Label(frame1, text = "Name :").pack(side = LEFT, padx=10, pady=10) # this is placed in 0 0
      # 'Entry' is used to display the input-field
        self.Name = Tkinter.Entry(frame1,width=24)
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.Name.insert(END, "New Flow Warden")
        self.Name.pack(side = LEFT) # this is placed in 0 1

        Tkinter.Label(frame2, text = "Mode :").pack(side = LEFT, padx=10, pady=10)
        self.mode_combo = Combobox(frame2)
        self.mode_combo['values']= (0,1, 2, 3, 4, 5)
        self.mode_combo.current(3) # 0 # 3  #set the selected item
        self.mode_combo.pack(side=tk.LEFT)
        
        Tkinter.Label(frame3, text = "i-IP").pack(side = LEFT, padx=10, pady=10)
      # 'Entry' is used to display the input-field
        self.ifaceIP1 = Tkinter.Entry(frame3,width=24)
        #self.C_Density.bind('<Return>', (lambda _: self.callback2(self.C_Density)))
        self.ifaceIP1.insert(END,"172.16.1.2")
        self.ifaceIP1.pack(side=tk.LEFT) # this is placed in 0 1

        Tkinter.Label(frame4, text = "o-IP").pack(side = LEFT, padx=10, pady=10)
      # 'Entry' is used to display the input-field
        self.ifaceIP2 = Tkinter.Entry(frame4,width=24)
        #self.P_Atm.bind('<Return>', (lambda _: self.callback3(self.P_Atm)))
        self.ifaceIP2.insert(END, "172.16.1.3")
        self.ifaceIP2.pack(side=tk.LEFT) # this is placed in 0 1

        Tkinter.Label(frame5, text = "Interface-i").pack(side = LEFT, padx=10, pady=10)
        self.ifacei = Tkinter.Entry(frame5,width=24)
        #self.Gama.bind('<Return>', (lambda _: self.callback4(self.Gama)))
        self.ifacei.insert(0, "enp0s8")
        self.ifacei.config(state='disabled') 
        self.ifacei.pack(side=tk.LEFT) # this is placed in 1 1

        Tkinter.Label(frame6, text = "Interface2").pack(side = LEFT, padx=10, pady=10)
        self.ifaceo = Tkinter.Entry(frame6,width=24)
        #self.Machno.bind('<Return>', (lambda _: self.callback5(self.Machno)))
        self.ifaceo.insert(0, "enp0s9")
        self.ifaceo.config(state='disabled')
        self.ifaceo.pack(side=tk.LEFT) # this is placed in 1 1


        #Rules
        group = Tkinter.LabelFrame(self.main_frame, text="Rules", padx=20, pady=20)
        group.place(x=520, y=100)

        frame1 = tk.Frame(group) ##, bg="#84CEEB")
        frame2 = tk.Frame(group) ##, bg="#84CEEB")
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
                      

        Tkinter.Label(frame1, text = "Net Flow Rules :").pack() # this is placed in 0 0
      # 'Entry' is used to display the input-field
        self.Flow_Rules = scrolledtext.ScrolledText(frame1,width=40,wrap='word',height=12)
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        ####################################################################
        # 95% rules used   
        ###################################################################
        #self.Flow_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48")
        ####################################################################
        # 50% rules used   
        ###################################################################
        #self.Flow_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26")
        ####################################################################
        # 5% rules used   
        ###################################################################
        self.Flow_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20")
        ###################################################################
        # No Rule Used - Gateway Mode or Static mode without rules 
        ###################################################################
        #self.Flow_Rules.insert(END, " ")
        self.Flow_Rules.pack() # this is placed in 0 1

        Tkinter.Label(frame2, text = "Packet Rules :").pack() # this is placed in 0 0
      # 'Entry' is used to display the input-field
        self.packet_Rules = scrolledtext.ScrolledText(frame2,width=40,wrap='word',height=12)
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        #self.packet_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48")
        #self.packet_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26")
        self.packet_Rules.insert(END, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20") 
        ##self.packet_Rules.insert(END, " ")
        self.packet_Rules.pack() # this is placed in 0 1

        #Rules
        group = Tkinter.LabelFrame(self.main_frame, text="Control", padx=0, pady=0)
        group.place(x=10, y=410)

        frame1 = tk.Frame(group) ##, bg="#84CEEB")
        frame2 = tk.Frame(group) ##, bg="#84CEEB")
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        Tkinter.Label(frame1, text = "Activity :").pack() # this is placed in 0 0
        self.activity = scrolledtext.ScrolledText(frame1,width=59,height=7)
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.activity.insert(END, "Warden Not Active Yet !\n")
        self.activity.pack() # this is placed in 0 1
           
        data=self.get_Props()
        self.b3=Tkinter.Button(frame2, text='Start', width = 6)
        self.b5=Tkinter.Button(frame2, text='Dashboard', width = 6)
        self.b4=Tkinter.Button(frame2, text='Stop', width = 6)
        try:
           
           
           self.b3=Tkinter.Button(frame2, text='Start',state='active', width = 6, command= lambda :self.start_warden_data(self.get_Props()))
           self.b4=Tkinter.Button(frame2, text='Stop',state='disabled', width = 6,command=lambda :self.stop_warden_data())
           self.b5=Tkinter.Button(frame2, text='Dashboard',state='disabled', width = 6,command=lambda: self.start_capture())

        
           self.b4.bind('<Button-1>',(lambda _: self.start_warden_data(self.get_Props())))
           self.b3.pack(side='left')
           self.b4.pack(side='left')
           self.b5.pack(side='left')
        except Exception as e:
           ##print('Failed Error : '+ str(e))
           pass
         
    def get_Props(self):
        #Name mode_combo ifaceIP1  ifaceIP2 ifaci ifaceo Flow_Rules packet_Rules activity
        
        self.NameX = self.Name.get()
        
        self.mode_comboX = abs(int(self.mode_combo.get()))
        self.ifaceIP1X =self.ifaceIP1.get()

        self.ifaceIP2X = self.ifaceIP2.get()
        self.ifaceiX = self.ifacei.get()
        self.ifaceoX= self.ifaceo.get()

        self.Flow_RulesX = self.Flow_Rules.get("1.0", Tkinter.END)
        self.packet_RulesX = self.packet_Rules.get("1.0", Tkinter.END)
        self.activityX = self.activity.get("1.0", Tkinter.END)
                       
        try:
           self.Refresh_Clear()
           self.Name.delete(0,END)
           self.Name.insert(END,self.NameX)
           #self.C_Pr.configure(text=abs(float(self.C_PrX)))

           self.mode_combo.delete(0,END)
           self.mode_combo.insert(END,abs(int(self.mode_comboX)))
           #self.C_Temp.configure(text=abs(float(self.C_TempX)))
           
           self.ifaceIP1.delete(0,END)
           self.ifaceIP1.insert(END,self.ifaceIP1X)
           #self.C_Density.configure(text=abs(float(self.C_DensityX)))

           self.ifaceIP2.delete(0,END)
           self.ifaceIP2.insert(END,self.ifaceIP2X)
           #self.P_Atm.configure(text=abs(float(self.P_AtmX)))
           
           self.ifacei.delete(0,END)
           self.ifacei.insert(END,self.ifaceiX)
           #self.Gama.configure(text=abs(float(self.GamaX)))

           self.ifaceo.delete(0,END)
           self.ifaceo.insert(END,self.ifaceoX)
           #self.Machno.configure(text=abs(float(self.MachnoX)))
                   
           self.Flow_Rules.delete(0,END)
           self.Flow_Rules.insert(END,self.Flow_RulesX)
           self.Flow_Rules.configure(text=self.Flow_RulesX)

           self.packet_Rules.delete(0,END)
           self.packet_Rules.insert(END,self.packet_RulesX)
           self.packet_Rules.configure(text=self.packet_RulesX)

           self.activity.delete(0,END)
           self.activity.insert(END,self.activityX)
           self.activity.configure(text=self.activityX)
                                                                     
           
        except Exception as e:
           #print('Failed Error 2 : '+ str(e))
           pass    
         
        if self.mode_comboX == 0 :
           #self.data = [self.NameX,'-i',self.ifaceIP1X,'-o',self.ifaceIP2X,'gateway','-fl',self.Flow_RulesX,'-pl',self.packet_RulesX]
           self.data = [self.NameX,'-i',self.ifaceIP1X,'-o',self.ifaceIP2X,'gateway']
        if self.mode_comboX in [ 1 ,2 ,3 , 4 , 5 ] :
           self.data = [self.NameX,'-i',self.ifaceIP1X,'-o',self.ifaceIP2X,'static','-fl',self.Flow_RulesX,'-pl',self.packet_RulesX]
        
        return self.data 
        #self.nozzleDisplay.intro_page(self,self)
   
    def set_Properties(self,data):
         self.NameX = data[0]
         self.mode_comboX = abs(int(data[1]))

         self.ifaceIP1X = data[2]
         self.ifaceIP2X = data[3]

         self.ifaceiX = data[4]
         self.ifaceoX = data[5]
         
         self.Flow_RulesX = data[6]
         self.packet_RulesX = data[7]
         self.activityX = data[8]
         
    def set_Stored_Data(self,ArrayObjectX):
        self.data = ArrayObjectX

    def get_Props_Data(self):
        return super().get_Props()

    def get_Stored_Data(self):
        return self.data

         
    def get_Properties(self):     
         #self.data = [self.C_PrX,self.C_TempX,self.C_DensityX,self.P_AtmX,self.GamaX,self.MachnoX,self.C_R_GasX,self.NXX,self.KXX,self.Exit_AngleX,self.L_Rt_RatioX,self.R_ThroatX,self.RcRtX]
         return self.data                 
         
    def Refresh_Clear(self):
       try:
       
        
        self.Name.delete(0,END)
        self.Name.insert(END,0)

        self.ifaceIP1.delete(0,END)
        self.ifaceIP1.insert(END,0)
        
        self.ifaceIP2.delete(0,END)
        self.ifaceIP2.insert(END,0)

        self.ifacei.delete(0,END)
        self.ifacei.insert(END,0)
        
        self.ifaceo.delete(0,END)
        self.ifaceo.insert(END,0)

        self.Flow_Rules.delete(0,END)
        self.Flow_Rules.insert(END,0)
                
        self.packet_Rules.delete(0,END)
        self.packet_Rules.insert(END,0)

        self.activity.delete(0,END)
        self.activity.insert(END,0)

        
       except Exception as e:
        #print('Failed Error 1 : '+ str(e))
        pass   
        
      
    def start_warden_data(self,data):
        self.controller.show_frame(PageOne)
        #kalaData = PageOne(self,self.controller,data)
        #kalaDataX = PageTwo(self,self.controller,PageTwo)
        
        #okDataX = PageThree(self,self.controller,self)
        #okDataX = PageFour(self,self.controller,self)
        
        #time.sleep(4)
        #self.controller.show_frame(PageTwo)
        #kalaDataX.display_Figure(data)
        #kalaDataX.label1.configure(text='data loaded ......')
        #kalaDataX.label1.update()
                
        self.activity.insert(END,'Warden Has Started ... \n')
        self.b3.config(state='disabled')
        self.b4.config(state='active')
        self.b5.config(state='active')
       
        FlowbasedFilter.initialize(data,self.activity,self.ifacei,self.ifaceo,self.label,self)

    def start_capture(self):
         
        if self.colour.get() == 'green':
               self.controller.show_frame(PageThree)
        else:
               self.stop_warden_data()
        
    def stop_warden_data(self):
        try:
               self.activity.insert(END,'Stopping Warden Program... \n')  
               FlowbasedFilter.reconfigure(self.activity,self.ifacei,self.ifaceo,self.label,self)
               #NetflowsStore.reportInExcel()
               FlowbasedFilter.printResourcesUsageStats()
               self.activity.insert(END,'Warden Has Stopped ... \n')
               self.b3.config(state='active')
               self.b4.config(state='disabled')
               self.b5.config(state='disabled')
               
        except KeyboardInterrupt:
               pass 
       
    def display_Figure(self,data):
        
        self.label.configure(text='NOZZLE PROPERTIES PAGE .......  Running command...')
        self.controller.show_frame(PageThree) 
        sendData = PageThree(self,self.controller,data)
        
        #time.sleep(4)
        self.label.configure(text='NOZZLE PROPERTIES PAGE ....... Finished running command...')
        
            

class PageThree(GUI):
    def __init__(self, parent, controller,classObject):
        GUI.__init__(self, parent)

        self.label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Graph-Page-Page Three")
        self.label1.pack(side="top")
        self.packet_in = 0
        self.controller=controller
        self.parent= parent
        self.data = []
        self.stopit = False
        self.t1 = None
        v = StringVar()
        v.trace('w',self.on_field_change)
        if (type(classObject) == list):
            self.data = classObject
            
        ##self.pageup = StartPage(self.parent,self.controller,classObject)
        
        # getting screen's height in pixels 
        height = controller.winfo_screenheight() 
  
      # getting screen's width in pixels 
        width = controller.winfo_screenwidth()
        
        #Packets in and out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=0)
        group.place(x=20, y=100)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame3 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame4 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)
        frame4.pack(side=tk.TOP)
        
        Tkinter.Label(frame1, text = "Packets In:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_in = Tkinter.Entry(frame1,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_in.insert(0, self.packet_in)
        self.packets_in.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1

        Tkinter.Label(frame2, text = "Packets Out:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_out = Tkinter.Entry(frame2,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_out.insert(END, 0)
        self.packets_out.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame3, text = "Packets In/Sec:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_in_sec = Tkinter.Entry(frame3,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_in_sec.insert(END, 0)
        self.packets_in_sec.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame4, text = "Packets Out/Sec:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_out_sec = Tkinter.Entry(frame4,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_out_sec.insert(END, 0)
        self.packets_out_sec.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        #Display Different types of graph 
        group = Tkinter.LabelFrame(self.main_frame,border=0, text=" ", padx=40, pady=40,bg="white")
        group.place(x=340, y=96)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame3 = tk.Frame(group,bg="white") ##, bg="#84CEEB")

        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)

        Tkinter.Label(frame1, text = "Activity Graph :",bg="white").pack() # this is placed in 0 0
        Tkinter.Label(frame2, text = "Type :",bg="white").pack(side = LEFT, padx=10, pady=10)
        self.graph_combo = Combobox(frame2,textvar=v)
        self.graph_combo['values']= ("OverView", "statistics", "NetFlow", "Updates")
        self.graph_combo.current(0) #set the selected item
        self.graph_combo.pack(side=tk.LEFT)
        self.graph_combo.bind('<<ComboboxSelected>>', self.on_field_change) 
        try:
           
           
           self.b4a=Tkinter.Button(frame3, text='Capture',state='active', width = 6,command=lambda :self.start_capture())
           self.b5a=Tkinter.Button(frame3, text='Stop',state='active', width = 6,command=lambda: self.stop_capture())

        
           #self.b4.bind('<Button-1>',(lambda _: self.start_capture(self.get_Props())))
           #self.b3.pack(side='left')
           self.b4a.pack(side='left')
           self.b5a.pack(side='left')
        except Exception as e:
           ##print('Failed Error : '+ str(e))
           pass
 
        #Data Bytes in out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=0)
        group.place(x=630, y=100)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame3 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame4 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)
        frame4.pack(side=tk.TOP)
                
        Tkinter.Label(frame1, text = "Data Recvd[MB]:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.data_recvd = Tkinter.Entry(frame1,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.data_recvd.insert(END, 0)
        self.data_recvd.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1

        Tkinter.Label(frame2, text = "Data Sent[MB]:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.data_sent = Tkinter.Entry(frame2,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.data_sent.insert(END, 0)
        self.data_sent.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame3, text = "Data Recvd[MB/sec]:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.data_recvd_sec = Tkinter.Entry(frame3,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.data_recvd_sec.insert(END, 0)
        self.data_recvd_sec.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame4, text = "Data Sent[MB/sec]:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.data_sent_sec = Tkinter.Entry(frame4,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.data_sent_sec.insert(END, 0)
        self.data_sent_sec.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1

        #Packets in and out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=10)
        group.place(x=20, y=260)
        
        self.fig,self.ax1,self.ax2 =  fig,ax1,ax2 
        self.ax1.set_title("Packets vs Time ")
        self.ax1.set_ylabel('Packets ')
        self.ax1.set_xlabel('Time (sec)')
        
        
        self.ax2.set_title("DatFlow vs Time ")
        self.ax2.set_ylabel('DataFlow ')
        self.ax2.set_xlabel('Time (sec)')
        
        self.fig.tight_layout()
        
        self.canvas = FigureCanvasTkAgg(self.fig,master=group)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side="bottom",fill="both",expand=False)
           
        #self.toolbar = NavigationToolbar2Tk(self.canvas,group)
        self.toolbar = NavigationToolbar2TkAgg(self.canvas,group)
        self.toolbar.update()
           
        self.canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        #self.canvas = FigureCanvasTkAgg(f,master=self)
        self.canvas.draw()
        #self.canvas.get_tk_widget().pack(side="top",fill='both',expand=True)
        
        #self.toolbar = NavigationToolbar2Tk(self.canvas, self)
        self.toolbar.update()
        
        #self.canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
        #time.sleep(1)
        #print("Plot Page has been cleared")
        #ani = animation.FuncAnimation(f, animate, interval=1000)
    def start_capture(self):
        try:
            
            tx1 = time.time()
            self.dashboard3 = self.controller.frames[PageOne] 
            self.dashboard = self.controller.frames[PageThree]               
            self.dashboard2 = self.controller.frames[PageFour]
            tx2 = time.time()- tx1
            print("booting time :" , tx2)
            self.t1 = threading.Thread(args=(self.dashboard3.data,self.dashboard3.activity,self.dashboard3.ifacei,self.dashboard3.ifaceo,self.dashboard3.label,self,self.dashboard2,self.dashboard3),target=FlowbasedFilter.run)
            # change T to daemon
            #self.t1.setDaemon(True)
            self.t1.start()
            tx3= time.time() - tx1
            print("booting time :" , tx3) 
            #FlowbasedFilter.run(self.dashboard3.data,self.dashboard3.activity,self.dashboard3.ifacei,self.dashboard3.ifaceo,self.dashboard3.label,self,self.dashboard2,self.dashboard3)
            tx4 = time.time() - tx1
            print("booting time :" , tx4) 
            time.sleep(5)
            self.t1.do_run = False
            print("booting time :" ,time.time()- tx1)
                        
        except Exception as e:
            print("Thread Exception in start capture function desc :" + str(e))
            print("Try to ping destination and check network settings for filter ..... Exiting Code .....")
            #self.t1.join()
            #sys.exit(0)
               
        
        FlowbasedFilter.printResourcesUsageStats(self.dashboard2,self.dashboard3)
        
        
    def stop_capture(self):
        try:
               self.t1.do_run = False
               
               self.dashboard3 = self.controller.frames[PageOne] 
               self.dashboard3.activity.insert(END,'Stopping Warden Program... \n')  
               FlowbasedFilter.reconfigure(self.dashboard3.activity,self.dashboard3.ifacei,self.dashboard3.ifaceo,self.dashboard3.label,self.dashboard3)
               #NetflowsStore.reportInExcel()
               FlowbasedFilter.printResourcesUsageStats()
               self.dashboard3.activity.insert(END,'Warden Has Stopped ... \n')
               self.b4a.config(state='active')
               self.b5a.config(state='disabled')
               
               
        except Exception as e:
               print("Exception :" + str(e))
               pass 

  
    def has_list_Changed(self,test_list_set,test_list_bisect):
      
       # code url :https://www.geeksforgeeks.org/python-ways-to-check-if-element-exists-in-list/                
       list_changed = False           
       
       for idx,value in enumerate(test_list_bisect):
          if test_list_bisect[idx]  in test_list_set :
             #print (test_list_bisect[idx]," Element Exists")
             pass
          else :
             #print (test_list_bisect[idx]," Element Does Not Exists")
             list_changed = True
           
      
       for idx,value in enumerate(test_list_set):
          if test_list_set[idx]  in test_list_bisect : 
             #print (test_list_set[idx]," Element Exists")
             pass
          else :
             #print (test_list_set[idx]," Element Does Not Exists")
             list_changed = True
             
       return list_changed
      

    def display_Figure(self,data):
        
        self.label.configure(text='NOZZLE PROPERTIES PAGE .......  Running command...')
        self.controller.show_frame(PageThree) 
        sendData = PageThree(self,self.controller,data)
        
        #time.sleep(4)
        self.label.configure(text='NOZZLE PROPERTIES PAGE ....... Finished running command...')
        
    def set_Stored_Data(self,ArrayObjectX):
        self.data = ArrayObjectX

    def get_Props_Data(self):
        return super().get_Props()

    def get_Stored_Data(self):
        return self.data
      
    def on_field_change(self, event) :
        if self.graph_combo.get() =='statistics':
              self.controller.show_frame(PageFour)
              self.dashboard= self.controller.frames[PageFour]
              FlowbasedFilter.printResourcesUsageStats(self.dashboard,self)
        
        print("combobox updated to ", self.graph_combo.get())

class PageFour(GUI):
    def __init__(self, parent, controller,classObject):
        GUI.__init__(self, parent)

        self.label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Page Four")
        self.label1.pack(side="top")
        self.Cpu_Usage = 0
        self.controller=controller
        self.parent= parent
        self.data = []
        v = StringVar()
        v.trace('w',self.on_field_change)
        if (type(classObject) == list):
            self.data = classObject
            
        ##self.pageup = StartPage(self.parent,self.controller,classObject)
        
        # getting screen's height in pixels 
        height = controller.winfo_screenheight() 
  
      # getting screen's width in pixels 
        width = controller.winfo_screenwidth()
        
        #Packets in and out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=0)
        group.place(x=20, y=100)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame3 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame4 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)
        frame4.pack(side=tk.TOP)
        
        Tkinter.Label(frame1, text = "Avg Mem Usage(MB):",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.Mem_Usage = Tkinter.Entry(frame1,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.Mem_Usage.insert(END, 0)
        self.Mem_Usage.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1

        Tkinter.Label(frame2, text = "CPU Time(sec):",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.CPU_Usage = Tkinter.Entry(frame2,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.CPU_Usage.insert(END, 0)
        self.CPU_Usage.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame3, text = "UPTIME ( secs ) :",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.up_time = Tkinter.Entry(frame3,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.up_time.insert(END, 0)
        self.up_time.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame4, text = "Packets Out/Sec:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_out = Tkinter.Entry(frame4,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_out.insert(END, 0)
        self.packets_out.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        #Display Different types of graph 
        group = Tkinter.LabelFrame(self.main_frame,border=0, text=" ", padx=40, pady=40,bg="white")
        group.place(x=340, y=96)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        Tkinter.Label(frame1, text = "Activity Graph :",bg="white").pack() # this is placed in 0 0
        Tkinter.Label(frame2, text = "Type :",bg="white").pack(side = LEFT, padx=10, pady=10)
        self.graph_combo = Combobox(frame2,textvar=v)
        self.graph_combo['values']= ("OverView", "statistics", "NetFlow", "Updates")
        self.graph_combo.current(2) #set the selected item
        self.graph_combo.pack(side=tk.LEFT)
        self.graph_combo.bind('<<ComboboxSelected>>', self.on_field_change) 

        #Data Bytes in out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=0)
        group.place(x=630, y=100)

        frame1 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame2 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame3 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        frame4 = tk.Frame(group,bg="white") ##, bg="#84CEEB")
        
        
        frame1.pack(side=tk.TOP)
        frame2.pack(side=tk.TOP)
        frame3.pack(side=tk.TOP)
        frame4.pack(side=tk.TOP)
                
        Tkinter.Label(frame1, text = "Forwarded Packets:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.forwarded_packets = Tkinter.Entry(frame1,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.forwarded_packets.insert(END, 0)
        self.forwarded_packets.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1

        Tkinter.Label(frame2, text = "Dropped Packets:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.dropped_packets = Tkinter.Entry(frame2,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.dropped_packets.insert(END, 0)
        self.dropped_packets.pack(side = RIGHT, ipadx=0, ipady=3, padx=30, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame3, text = "Normalized Packets :",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=20, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.normalized_packets = Tkinter.Entry(frame3,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.normalized_packets.insert(END, 0)
        self.normalized_packets.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1
        
        Tkinter.Label(frame4, text = "Packets Out:",bg="white", relief='flat',anchor="w").pack(side = LEFT, ipadx=16, ipady=3) # this is placed in 0 0
        # 'Entry' is used to display the input-field
        self.packets_out = Tkinter.Entry(frame4,font="Arial",width=14, relief='flat')
        #self.C_Pr.bind('<Return>', (lambda _: self.callback(self.C_Pr)))
        self.packets_out.insert(END, 0)
        self.packets_out.pack(side = LEFT, ipadx=0, ipady=3, padx=15, pady=3) # this is placed in 0 1

        #Packets in and out for the warden 
        group = groupX = Tkinter.LabelFrame(self,border=0, text=" ",bg="white", padx=10, pady=10)
        group.place(x=20, y=260)
       
        self.fig1,self.ax3,self.ax4 =  fig1,ax3,ax4 
        self.ax3.set_title("System Statistics vs Time")
        self.ax3.set_ylabel('CPU/RAM/UPTIME')
        self.ax3.set_xlabel('Time (sec)')
               
        self.ax4.set_title("Packets vs Time ")
        self.ax4.set_ylabel('Packets ')
        self.ax4.set_xlabel('Time (sec)')
        
        self.fig1.tight_layout()
        
        self.canvas = FigureCanvasTkAgg(self.fig1,master=group)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side="bottom",fill="both",expand=False)
           
        #self.toolbar = NavigationToolbar2Tk(self.canvas,group)
        self.toolbar = NavigationToolbar2TkAgg(self.canvas,group)  
        self.toolbar.update()
           
        self.canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        #self.canvas = FigureCanvasTkAgg(f,master=self)
        self.canvas.draw()
        #self.canvas.get_tk_widget().pack(side="top",fill='both',expand=True)
        
        #self.toolbar = NavigationToolbar2Tk(self.canvas, self)
        self.toolbar.update()
        
        #self.canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
        #time.sleep(1)
        #print("Plot Page has been cleared")
        #ani = animation.FuncAnimation(f, animate, interval=1000)
  
    def has_list_Changed(self,test_list_set,test_list_bisect):
      
       # code url :https://www.geeksforgeeks.org/python-ways-to-check-if-element-exists-in-list/                
       list_changed = False           
       
       for idx,value in enumerate(test_list_bisect):
          if test_list_bisect[idx]  in test_list_set :
             #print (test_list_bisect[idx]," Element Exists")
             pass
          else :
             #print (test_list_bisect[idx]," Element Does Not Exists")
             list_changed = True
           
      
       for idx,value in enumerate(test_list_set):
          if test_list_set[idx]  in test_list_bisect : 
             #print (test_list_set[idx]," Element Exists")
             pass
          else :
             #print (test_list_set[idx]," Element Does Not Exists")
             list_changed = True
             
       return list_changed

    def display_Figure(self,data):
        
        self.label.configure(text='NOZZLE PROPERTIES PAGE .......  Running command...')
        self.controller.show_frame(PageThree) 
        sendData = PageThree(self,self.controller,data)
        
        #time.sleep(4)
        self.label.configure(text='NOZZLE PROPERTIES PAGE ....... Finished running command...')
   
    def set_Stored_Data(self,ArrayObjectX):
        self.data = ArrayObjectX

    def get_Props_Data(self):
        return super().get_Props()

    def get_Stored_Data(self):
        return self.data
      
    def on_field_change(self, event) :
        if self.graph_combo.get() =='OverView':
              self.controller.show_frame(PageThree)
              self.dashboard= self.controller.frames[PageThree]
              FlowbasedFilter.printResourcesUsageStats(self,self.dashboard)
        
        print("combobox updated to ", self.graph_combo.get())

      
class PageTwo(GUI):
    def __init__(self, parent, controller,classObject):
        GUI.__init__(self, parent)

        self.label = tk.Label(self.main_frame, font=("Verdana", 20), text="Page Two")
        self.label.pack(side="top")

        self.label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="NetFlow Statistics")
        self.label1.pack(side="top")
        
        if type(classObject) == list:
            wardenName = classObject
            self.label1.configure(text = wardenName)
            self.label1.update()
            print(wardenName)
        elif isinstance(classObject,PageOne):
            self.label1.configure(text ="Page One Class Object passed")
         
        elif isinstance(classObject,PageTwo):
            self.label1.configure(text ="Page Two Class Object passed")

        elif isinstance(classObject,PageThree):
            self.label1.configure(text ="Page Three Class Object passed")

        elif isinstance(classObject,PageFour):
            self.label1.configure(text ="Page Four Class Object passed")
        else:
             self.label1.configure(text =type(classObject))
           
        
    def display_Figure(self,data):
        print(data)
        self.label1.configure(text='NOZZLE PROPERTIES PAGE .......  Running command...')
        #self.controller.show_frame(PageThree) 
        #sendData = PageThree(self,self.controller,data)
        
        #time.sleep(4)
        self.label1.configure(text='NOZZLE PROPERTIES PAGE ....... Finished running command...')
    def set_Stored_Data(self,ArrayObjectX):
        self.data = ArrayObjectX

    def get_Props_Data(self):
        return super().get_Props()

    def get_Stored_Data(self):
        return self.data    


class OpenNewWindow(tk.Tk):

    def __init__(self, *args, **kwargs):

        tk.Tk.__init__(self, *args, **kwargs)

        main_frame = tk.Frame(self)
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        self.title("Here is the Title of the Window")
        self.geometry("500x500")
        self.resizable(0, 0)

        frame1 = ttk.LabelFrame(main_frame, text="This is a ttk LabelFrame")
        frame1.pack(expand=True, fill="both")

        label1 = tk.Label(frame1, font=("Verdana", 20), text="OpenNewWindow Page")
        label1.pack(side="top")

      

app = FlowWardenProject()
app.mainloop()
        
