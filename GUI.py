from File_locker import *
from tkinter import *
class GUI():
    def __init__(self, line1='Username', line2='Password', title='Log in', command_OK=None, change_pass=False, command_change=None):
        self.user_name = None
        self.password = None
        self.root = Tk()
        self.root.title(title)
        self.info = StringVar()
        self.passStatus = IntVar()
        if line1 != None:
            self.v1 = StringVar()
            self.l1_content = StringVar()
            self.l1_content.set(line1)
            self.l1 = Label(self.root, textvariable=self.l1_content)
            self.l1.grid(row=0, column=0, sticky=W)  # label：文本
        self.l2_content = StringVar()
        self.l2_content.set(line2)
        self.l2 = Label(
            self.root, textvariable=self.l2_content)  # grid：表格结构
        self.l2.grid(row=1, column=0, sticky=W)
        self.v2 = StringVar()
        self.e2 = Entry(self.root, textvariable=self.v2, show='*')  # 想显示什么就show=
        self.e2.grid(row=1, column=1, padx=10, pady=5)
        if not line1 == None:
            self.e1 = Entry(self.root, textvariable=self.v1, show='*')
            self.e1.grid(row=0, column=1, padx=10, pady=5)
            self.e1.focus_set()  # entry：输入框
        else:
            self.e2.focus_set()

        def change_pass_status():
            for k, (i, var) in enumerate([(self.e2, self.v2), (self.e1, self.v1)]
                                            if hasattr(self, 'e1') else [(self.e2, self.v2)]):
                # 为了只写一遍代码就整出了这么复杂的一个东西😅
                if self.passStatus.get() == 0:
                    i.grid_forget()
                    i = Entry(self.root, textvariable=var)  # 想显示什么就show=
                    # k是为了使遍历到e1时grid设为0，到e2时grid设为1
                    i.grid(row=1-k, column=1, padx=10, pady=5)
                else:
                    i.grid_forget()
                    i = Entry(self.root, textvariable=var,
                                show='*')  # 想显示什么就show=
                    i.grid(row=1-k, column=1, padx=10, pady=5)
        self.showpass = Checkbutton(self.root, text='Show Password', command=change_pass_status, variable=self.passStatus,
                                    onvalue=0, offvalue=1)
        self.showpass.deselect()
        self.showpass.grid(row=3, column=2 if change_pass else 1, sticky=E)

        def command(*args): #*args不可删除，否则会导致回车键绑定出问题

            if hasattr(self, 'v1'):
                if self.v1.get() != '' and self.v2.get() != '':
                    self.user_name = self.v1.get()
                    self.password = self.v2.get()
                    if callable(command_OK):
                        command_OK(*self.OKargs, **self.OKkwargs)
                else:
                    messagebox.showinfo(
                        'WARNING', 'Please fill in all the blanks')
            else:
                if self.v2.get() != '':
                    self.password = self.v2.get()
                    if callable(command_OK):
                        command_OK(*self.OKargs, **self.OKkwargs)
                else:
                    messagebox.showinfo(
                        'WARNING', 'Please fill in all the blanks')

        def exec_command_change():
            command_change(*self.change_pass_command_args, **self.change_pass_command_kwargs)
        self.b1 = Button(self.root, text='OK', width=8, command=command)
        self.b1.grid(row=6, column=0, sticky=W, padx=8, pady=10)
        self.b2 = Button(self.root, text='exit', width=10, command=self.root.destroy)
        self.b2.grid(row=6, column=1, sticky=N, padx=10, pady=10)
        if change_pass:
            self.b3 = Button(self.root, text='change password', width=20, command=exec_command_change)
            self.b3.grid(row=6, column=2, sticky=E, padx=20, pady=10)
        self.l3 = Label(self.root, textvariable=self.info)
        self.l3.grid(row=2, column=0, columnspan=3, sticky=W)
        self.root.bind("<Return>", command)
        self.OKargs = []
        self.OKkwargs = {}
        self.change_pass_command_args = []
        self.change_pass_command_kwargs = {}

    def set_l1(self, value):
        self.l1_content.set(value)

    def set_l2(self, value):
        self.l2_content.set(value)

    def message(self, message):
        messagebox.showinfo('info', message=message)

    def loop(self):
        self.root.mainloop()

    def set_command_OK_params(self, *args, **kwargs):
        self.OKargs = args
        self.OKkwargs = kwargs

    def set_command_change_pass_params(self, *args, **kwargs):
        self.change_pass_command_args = args
        self.change_pass_command_kwargs = kwargs

    def destroy(self):
        '''All widgets will be removed!!'''
        self.root.destroy()