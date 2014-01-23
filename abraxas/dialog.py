# Account Select Dialog Box

# Requires the python bindings for the GTK3 library.

from gi.repository import Gtk as gtk
from gi.repository import Gdk as gdk

class ListDialog (gtk.Window):

    def __init__(self, accounts):
        gtk.Window.__init__(self)
        self.set_type_hint(gdk.WindowTypeHint.DIALOG)
        #self.add_events(gdk.KEY_PRESS_MASK)
        self.connect('key_press_event', self.on_hotkey)
        self.connect("destroy", self.cancel)

        self.model = gtk.ListStore(str)
        self.view = gtk.TreeView(self.model)

        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Account", cell, text=0)
        self.view.append_column(column)

        self.choice = None
        self.accounts = accounts

        for account in accounts:
            row = self.model.append()
            self.model.set(row, 0, account)

        self.add(self.view)

    def run(self):
        self.show_all()
        gtk.main()
        return self.choice

    def cancel(self, *args):
        self.choice = None
        gtk.main_quit()

    def on_hotkey(self, widget, event):
        key = gdk.keyval_name(event.keyval)
        selection = self.view.get_selection()
        model, iter = selection.get_selected()
        path = self.model.get_path(iter)

        scroll = lambda path, dx: (path[0] + dx) % len(self.accounts)
        #print(self.view.has_focus())

        if key == 'j':
            #path = scroll(path, 1)
            #iter = self.model.get_iter(path)
            #selection.select_iter(iter)
            self.view.set_cursor(scroll(path, 1))
            self.view.grab_focus()
        elif key == 'k':
            #path = scroll(path, 1)
            #iter = self.model.get_iter(path)
            #selection.select_iter(iter)
            self.view.set_cursor(scroll(path, -1))
            self.view.grab_focus()
        elif key == 'Return':
            iter = self.model.get_iter(path[0])
            self.choice = self.model.get_value(iter, 0)
            gtk.main_quit()
        elif key == 'Escape':
            self.cancel()

        return True


class ErrorDialog (gtk.MessageDialog):

    def __init__(self, message, description=None):
        gtk.MessageDialog.__init__(self,
                type=gtk.MessageType.ERROR,
                buttons=gtk.ButtonsType.OK,
                message_format=message)

        if description:
            self.format_secondary_text(description)



def show_list_dialog(accounts):
    dialog = ListDialog(accounts)
    return dialog.run()

def show_error_dialog(message):
    dialog = ErrorDialog(message)
    return dialog.run()
