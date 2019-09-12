# -*- coding: utf-8 -*-
# pylint: disable=unsubscriptable-object
""" Changed for DIRAC. Beautiful terminal spinners in Python. Source: https://github.com/manrajgrover/halo
"""
from __future__ import absolute_import, unicode_literals

import os
import re
import sys
import six
import time
import atexit
import signal
import codecs
import platform
import functools
import threading
try:
    from shutil import get_terminal_size
except ImportError:
    from backports.shutil_get_terminal_size import get_terminal_size

def colored(text, color=None, on_color=None, attrs=None):
    """ Colorize text, while stripping nested ANSI color sequences.
        
        :param basestring text: text
        :param basestring color: text colors -> red, green, yellow, blue, magenta, cyan, white.
        :param basestring on_color: text highlights -> on_red, on_green, on_yellow, on_blue, on_magenta, on_cyan, on_white.
        :param list attrs: attributes -> bold, dark, underline, blink, reverse, concealed.
        --
            colored('Hello, World!', 'red', 'on_grey', ['blue', 'blink'])
            colored('Hello, World!', 'green')
    """
    ATTRIBUTES = dict(list(zip(['bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed'],
                  list(range(1, 9)))))
    del ATTRIBUTES['']
    ATTRIBUTES_RE = '\033\[(?:%s)m' % '|'.join(['%d' % v for v in ATTRIBUTES.values()])
    HIGHLIGHTS = dict(list(zip(['on_grey', 'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white'],
                    list(range(40, 48)))))
    HIGHLIGHTS_RE = '\033\[(?:%s)m' % '|'.join(['%d' % v for v in HIGHLIGHTS.values()])
    COLORS = dict(list(zip(['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',],
                list(range(30, 38)))))
    COLORS_RE = '\033\[(?:%s)m' % '|'.join(['%d' % v for v in COLORS.values()])
    RESET = '\033[0m'
    RESET_RE = '\033\[0m'
    
    if os.getenv('ANSI_COLORS_DISABLED') is None:
        fmt_str = '\033[%dm%s'
        if color is not None:
            text = re.sub(COLORS_RE + '(.*?)' + RESET_RE, r'\1', text)
            text = fmt_str % (COLORS[color], text)
        if on_color is not None:
            text = re.sub(HIGHLIGHTS_RE + '(.*?)' + RESET_RE, r'\1', text)
            text = fmt_str % (HIGHLIGHTS[on_color], text)
        if attrs is not None:
            text = re.sub(ATTRIBUTES_RE + '(.*?)' + RESET_RE, r'\1', text)
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)
        return text + RESET
    else:
        return text

class StreamWrapper(object):
    """ Wraps a stream (such as stdout), acting as a transparent proxy for all
        attribute access apart from method 'write()', which is delegated to our
        Converter instance.
    """
    def __init__(self, wrapped, converter):
        # double-underscore everything to prevent clashes with names of
        # attributes on the wrapped stream object.
        self.__wrapped = wrapped
        self.__convertor = converter

    def __getattr__(self, name):
        return getattr(self.__wrapped, name)

    def __enter__(self, *args, **kwargs):
        # special method lookup bypasses __getattr__/__getattribute__, see
        # https://stackoverflow.com/questions/12632894/why-doesnt-getattr-work-with-exit
        # thus, contextlib magic methods are not proxied via __getattr__
        return self.__wrapped.__enter__(*args, **kwargs)

    def __exit__(self, *args, **kwargs):
        return self.__wrapped.__exit__(*args, **kwargs)

    def write(self, text):
        self.__convertor.write(text)

    def isatty(self):
        stream = self.__wrapped
        if 'PYCHARM_HOSTED' in os.environ:
            if stream is not None and (stream is sys.__stdout__ or stream is sys.__stderr__):
                return True
        try:
            stream_isatty = stream.isatty
        except AttributeError:
            return False
        else:
            return stream_isatty()

    @property
    def closed(self):
        stream = self.__wrapped
        try:
            return stream.closed
        except AttributeError:
            return True


class PreWrapp(object):
    def __init__(self, wrapped):
      if os.name == 'nt':
        raise BaseException('Not support')
      # The wrapped stream (normally sys.stdout or sys.stderr)
      self.wrapped = wrapped
      # create the proxy wrapping our output stream
      self.stream = StreamWrapper(wrapped, self)

    def write(self, text):
        self.wrapped.write(text)
        self.wrapped.flush()
        self.reset_all()

    def reset_all(self):
        if not self.stream.closed:
            self.wrapped.write('\033[0m')


def reset_all():
    if PreWrapp is not None:    # Issue #74: objects might become None at exit
        PreWrapp(sys.stdout).reset_all()

sys.stdout = PreWrapp(sys.stdout).stream
sys.stderr = PreWrapp(sys.stderr).stream
atexit.register(reset_all)

def is_supported():
    """ Check whether operating system supports main symbols or not.

        :return: boolen -- Whether operating system supports main symbols or not
    """
    return platform.system() != 'Windows'

def get_environment():
    """ Get the environment in which halo is running

        :return: basestring -- Environment name
    """
    try:
        from IPython import get_ipython
    except ImportError:
        return 'terminal'
    try:
        shell = get_ipython().__class__.__name__
        if shell == 'ZMQInteractiveShell':  # Jupyter notebook or qtconsole
            return 'jupyter'
        elif shell == 'TerminalInteractiveShell':  # Terminal running IPython
            return 'ipython'
        else:
            return 'terminal'  # Other type (?)
    except NameError:
        return 'terminal'

def colored_frame(frame, color):
    """ Color the frame with given color and returns.

        :param basestring frame: Frame to be colored
        :param basestring color: Color to be applied

        :return: basestring -- Colored frame
    """
    return colored(frame, color, attrs=['bold'])

def is_text_type(text):
    """ Check if given parameter is a string or not
        
        :param basestring text: Parameter to be checked for text type

        :return: boolen -- Whether parameter is a string or not
    """
    return bool(isinstance(text, six.text_type) or isinstance(text, six.string_types))

def decode_utf_8_text(text):
    """ Decode the text from utf-8 format

        :param basestring text: String to be decoded

        :return: basestring -- Decoded string
    """
    try:
        return codecs.decode(text, 'utf-8')
    except (TypeError, ValueError):
        return text

def encode_utf_8_text(text):
    """ Encodes the text to utf-8 format

        :param basestring text: String to be encoded
        
        :return: basestring -- Encoded string
    """
    try:
        return codecs.encode(text, 'utf-8', 'ignore')
    except (TypeError, ValueError):
        return text

def get_terminal_columns():
    """ Determine the amount of available columns in the terminal

        :return: int -- Terminal width
    """
    terminal_size = get_terminal_size()
    # If column size is 0 either we are not connected
    # to a terminal or something else went wrong. Fallback to 80.
    return 80 if terminal_size.columns == 0 else terminal_size.columns


class Halo(object):
    """ Halo library.

        CLEAR_LINE -- Code to clear the line
    """
    # Need for cursor
    if os.name == 'nt':
        import ctypes
        class _CursorInfo(ctypes.Structure):
            _fields_ = [("size", ctypes.c_int), ("visible", ctypes.c_byte)]
    
    CLEAR_LINE = '\033[K'
    SPINNER_PLACEMENTS = ('left', 'right',)

    def __init__(self, text='', color='green', text_color=None, spinner=None,
                 animation=None, placement='left', interval=-1, enabled=True, stream=sys.stdout):
        """ Constructs the Halo object.

            :param basestring text: Text to display.
            :param basestring color: Color of the text.
            :param basestring text_color: Color of the text to display.
            :param basestring,dict spinner: String or dictionary representing spinner.
            :param basesrting animation: Animation to apply if text is too large. Can be one of `bounce`, `marquee`.
                   Defaults to ellipses.
            :param basestring placement: Side of the text to place the spinner on. Can be `left` or `right`.
                   Defaults to `left`.
            :param int interval: Interval between each frame of the spinner in milliseconds.
            :param boolean enabled: Spinner enabled or not.
            :param io stream: IO output.
        """
        self._color = color
        self._animation = animation
        self.spinner = spinner
        self.text = text
        self._text_color = text_color
        self._interval = int(interval) if int(interval) > 0 else self._spinner['interval']
        self._stream = stream
        self.placement = placement
        self._frame_index = 0
        self._text_index = 0
        self._spinner_thread = None
        self._stop_spinner = None
        self._spinner_id = None
        self.enabled = enabled
        environment = get_environment()
        
        def clean_up():
            """ Handle cell execution"""
            self.__stop()

        if environment in ('ipython', 'jupyter'):
            from IPython import get_ipython
            ip = get_ipython()
            ip.events.register('post_run_cell', clean_up)
        else:  # default terminal
            atexit.register(clean_up)

    def __enter__(self):
        """ Starts the spinner on a separate thread. For use in context managers.
        """
        return self.start()

    def __exit__(self, eType, eValue, traceback):
        """ Stops the spinner. For use in context managers."""
        if eType:
            if isinstance(eValue, SystemExit) and eValue.code in [None, 0]:
                self.succeed()
            else:
                self.fail(eValue.message if isinstance(eValue.message, str) else None)
        else:
            self.succeed()

    def __call__(self, f):
        """ Allow the Halo object to be used as a regular function decorator.
        """
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            with self:
                return f(*args, **kwargs)
        return wrapped

    @property
    def spinner(self):
        """ Getter for spinner property.
        
            :return: dict -- spinner value
        """
        return self._spinner

    @spinner.setter
    def spinner(self, spinner=None):
        """ Setter for spinner property.
        
            :param dict,basestring spinner: Defines the spinner value with frame and interval
        """
        self._spinner = {"interval": 80, "frames": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]}
        self._frame_index = 0
        self._text_index = 0

    @property
    def text(self):
        """ Getter for text property.
            
            :return: basestring -- text value
        """
        return self._text['original']

    @text.setter
    def text(self, text):
        """ Setter for text property.
        
            :param basestring text: Defines the text value for spinner
        """
        self._text = self._get_text(text)

    @property
    def text_color(self):
        """ Getter for text color property.
        
            :return: basestring -- text color value
        """
        return self._text_color

    @text_color.setter
    def text_color(self, text_color):
        """ Setter for text color property.
        
            :param basestring text_color: Defines the text color value for spinner
        """
        self._text_color = text_color

    @property
    def color(self):
        """ Getter for color property.
        
            :return: basestring -- color value
        """
        return self._color

    @color.setter
    def color(self, color):
        """ Setter for color property.
        
            :param basestring color: Defines the color value for spinner
        """
        self._color = color

    @property
    def placement(self):
        """ Getter for placement property.
            
            :return: basestring -- spinner placement
        """
        return self._placement

    @placement.setter
    def placement(self, placement):
        """ Setter for placement property.
        
            :param basestring placement: Defines the placement of the spinner
        """
        if placement not in self.SPINNER_PLACEMENTS:
            raise ValueError("Unknown spinner placement '{0}', available are {1}".format(placement, self.SPINNER_PLACEMENTS))
        self._placement = placement

    @property
    def spinner_id(self):
        """ Getter for spinner id
        
            :return: basestring -- Spinner id value
        """
        return self._spinner_id

    @property
    def animation(self):
        """ Getter for animation property.
            
            :return: basestring -- Spinner animation
        """
        return self._animation

    @animation.setter
    def animation(self, animation):
        """ Setter for animation property.
        
            :param basestring animation: Defines the animation of the spinner
        """
        self._animation = animation
        self._text = self._get_text(self._text['original'])

    def _check_stream(self):
        """ Returns whether the stream is open, and if applicable, writable

            :return: bool -- Whether the stream is open
        """
        if self._stream.closed:
            return False
        try:
            # Attribute access kept separate from invocation, to avoid
            # swallowing AttributeErrors from the call which should bubble up.
            check_stream_writable = self._stream.writable
        except AttributeError:
            pass
        else:
            return check_stream_writable()
        return True

    def _write(self, s):
        """ Write to the stream, if writable

            :params basestring s: Characters to write to the stream
        """
        if self._check_stream():
            self._stream.write(s)

    def _hide_cursor(self):
        """ Disable the user's blinking cursor
        """
        if self._check_stream() and self._stream.isatty():
            # for sid in [signal.SIGINT, signal.SIGTSTP]:
            #     signal.signal(sid, self._show_cursor)
            if os.name == 'nt':
                ci = _CursorInfo()
                handle = ctypes.windll.kernel32.GetStdHandle(-11)
                ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
                ci.visible = False
                ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))
            elif os.name == 'posix':
                sys.stdout.write("\033[?25l")
                sys.stdout.flush()

    def _show_cursor(self, *args):
        """ Re-enable the user's blinking cursor
        """
        if self._check_stream() and self._stream.isatty():
            if os.name == 'nt':
                ci = _CursorInfo()
                handle = ctypes.windll.kernel32.GetStdHandle(-11)
                ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
                ci.visible = True
                ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))
            elif os.name == 'posix':
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()

    def _get_text(self, text):
        """ Creates frames based on the selected animation

            :params basestring text: text
        """
        animation = self._animation
        stripped_text = text.strip()

        # Check which frame of the animation is the widest
        max_spinner_length = max([len(i) for i in self._spinner['frames']])
        
        # Subtract to the current terminal size the max spinner length
        # (-1 to leave room for the extra space between spinner and text)
        terminal_width = get_terminal_columns() - max_spinner_length - 1
        text_length = len(stripped_text)
        frames = []
        if terminal_width < text_length and animation:

            if animation == 'bounce':
                # Make the text bounce back and forth
                for x in range(0, text_length - terminal_width + 1):
                    frames.append(stripped_text[x:terminal_width + x])
                frames.extend(list(reversed(frames)))

            elif 'marquee':
                # Make the text scroll like a marquee
                stripped_text = stripped_text + ' ' + stripped_text[:terminal_width]
                for x in range(0, text_length + 1):
                    frames.append(stripped_text[x:terminal_width + x])

        elif terminal_width < text_length and not animation:
            # Add ellipsis if text is larger than terminal width and no animation was specified
            frames = [stripped_text[:terminal_width - 4] + '... ']
        else:
            frames = [stripped_text]
        return {'original': text, 'frames': frames}

    def clear(self):
        """ Clears the line and returns cursor to the start.
        """
        self._write('\r')
        self._write(self.CLEAR_LINE)
        return self

    def _render_frame(self):
        """ Renders the frame on the line after clearing it.
        """
        if not self.enabled:
            # in case we're disabled or stream is closed while still rendering,
            # we render the frame and increment the frame index, so the proper
            # frame is rendered if we're reenabled or the stream opens again.
            return
        self.clear()
        frame = self.frame()
        output = '\r{}'.format(frame)
        try:
            self._write(output)
        except UnicodeEncodeError:
            self._write(encode_utf_8_text(output))

    def render(self):
        """ Runs the render until thread flag is set.
        """
        while not self._stop_spinner.is_set():
            self._render_frame()
            time.sleep(0.001 * self._interval)
        return self

    def frame(self):
        """ Builds and returns the frame to be rendered
        """
        frames = self._spinner['frames']
        frame = frames[self._frame_index]
        if self._color:
            frame = colored_frame(frame, self._color)
        self._frame_index += 1
        self._frame_index = self._frame_index % len(frames)
        text_frame = self.text_frame()
        return u'{0} {1}'.format(*[(text_frame, frame) if self._placement == 'right' else (frame, text_frame)][0])

    def text_frame(self):
        """ Builds and returns the text frame to be rendered
        """
        if len(self._text['frames']) == 1:
            if self._text_color:
                return colored_frame(self._text['frames'][0], self._text_color)
            # Return first frame (can't return original text because at this point it might be ellipsed)
            return self._text['frames'][0]
        frames = self._text['frames']
        frame = frames[self._text_index]
        self._text_index += 1
        self._text_index = self._text_index % len(frames)
        return colored_frame(frame, self._text_color) if self._text_color else frame

    def start(self, text=None):
        """ Starts the spinner on a separate thread.
        
            :param basestring text: Text to be used alongside spinner
        """
        if text is not None:
            self.text = text
        if self._spinner_id is not None:
            return self
        if not (self.enabled and self._check_stream()):
            return self
        #self._hide_cursor()
        self._stop_spinner = threading.Event()
        self._spinner_thread = threading.Thread(target=self.render)
        self._spinner_thread.setDaemon(True)
        self._render_frame()
        self._spinner_id = self._spinner_thread.name
        self._spinner_thread.start()
        return self
    
    def __stop(self):
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._stop_spinner.set()
            self._spinner_thread.join()

        if self.enabled:
            self.clear()

        self._frame_index = 0
        self._spinner_id = None
        self._show_cursor()
        return self

    def succeed(self, text=None):
        """ Shows and persists success symbol and text and exits.
        
            :param basestring text: Text to be shown alongside success symbol.
        """
        self._color = 'green'
        return self.stop(symbol='✔', text=text)

    def fail(self, text=None):
        """ Shows and persists fail symbol and text and exits.
            
            :param basestring text: Text to be shown alongside fail symbol.
        """
        self._color = 'red'
        return self.stop(symbol='✖', text=text)

    def warn(self, text=None):
        """ Shows and persists warn symbol and text and exits.
        
            :param basestring text: Text to be shown alongside warn symbol.
        """
        self._color = 'yellow'
        return self.stop(symbol='⚠', text=text)

    def info(self, text=None):
        """ Shows and persists info symbol and text and exits.
        
            :param basestring text: Text to be shown alongside info symbol.
        """
        self._color = 'blue'
        return self.stop(symbol='ℹ', text=text)
    
    def stop(self, text=None, symbol=None):
        """ Stops the spinner and persists the final frame to be shown.

            :param basestring text: Text to be shown in final frame
            :param basestring symbol: Symbol to be shown in final frame
        """
        if not (symbol and text):
            self.__stop()
        if not self.enabled:
            return self
        self.__stop()
        symbol = decode_utf_8_text(symbol) if symbol is not None else ''
        text = decode_utf_8_text(text) if text is not None else self._text['original']
        symbol = colored_frame(symbol, self._color) if self._color and symbol else symbol
        text = colored_frame(text, self._text_color) if self._text_color and text else text.strip()
        output = u'{0} {1}\n'.format(*[(text, symbol) if self._placement == 'right' else (symbol, text)][0])
        try:
            self._write(output)
        except UnicodeEncodeError:
            self._write(encode_utf_8_text(output))
        return self
