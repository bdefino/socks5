# Copyright 2018 Bailey Defino
# <https://bdefino.github.io>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import Queue
import thread

__doc__ = "threaded multitasking"

class Synchronized:
    """synchronized access to an object"""

    def __init__(self, value = None):
        self._lock = thread.allocate_lock()
        self.value = value

    def callattr(self, attr = "__call__", *args, **kwargs):
        with self._lock:
            return getattr(self.value, attr)(*args, **kwargs)

    def get(self):
        with self._lock:
            return self.value

    def getattr(self, attr):
        with self._lock:
            return getattr(self.value, attr)

    def set(self, value = None):
        with self._lock:
            self.value = value

    def setattr(self, attr, value = None):
        with self._lock:
            setattr(self.value, attr, value)

    def transform(self, func):
        with self._lock:
            self.value = func(self.value)

class Task:
    """
    an interface for a task

    tasks don't have to subclass this,
    as a task is simply something callable

    note that __call__ accepts arguments
    """
    
    def __init__(self):
        pass

    def __call__(self, *args, **kwargs):
        """execute the task"""
        pass

class IterableTask(Task):
    """
    an interface for a multipart task

    note that __call__ and next don't accept arguments
    """

    def __init__(self):
        Task.__init__(self)

    def __call__(self):
        """execute the entire task"""
        for part in self:
            pass

    def __iter__(self):
        return self

    def next(self):
        """execute the next part of the task"""
        raise StopIteration()

class TaskInfo:
    """information about a task"""

    def __init__(self, task, output = None, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.output = output
        self.task = task

class Threaded:
    """
    base class for a thread allocator

    in order to preserve return values, this behaves like a queue:
    both the get and put operations are supported

    nthreads may be used to specify various behaviors:
        nthreads < 0
            -> a thread is spawned for each task
        nthreads == 0
            -> tasks are run in the current thread
        nthreads > 0
            -> up to nthreads tasks execute simultaneously
    """

    def __init__(self, nthreads = -1, queue_output = False):
        self.nactive = Synchronized(0) # the number of active threads
        self.nthreads = nthreads
        
        if queue_output:
            self._output_queue = Queue.Queue()

    def get(self):
        """if queue_output was specified, return a TaskInfo instance"""
        if hasattr(self, "_output_queue"):
            return getattr(self, "_output_queue").get()
        raise AttributeError("queue_output wasn't specified")

    def _handle_task(self, task, *args, **kwargs):
        """handle a task, and queue its info as needed"""
        output = None

        try:
            output = task(*args, **kwargs)
        except Exception as output:
            pass
        
        if hasattr(self, "_output_queue"):
            getattr(self, "_output_queue").put(TaskInfo(task, output, *args,
                **kwargs))

        if not self.nthreads == 0: # inform the allocator
            self.nactive.transform(lambda n: n - 1)

    def put(self, task, *args, **kwargs):
        """allocate space for a task, optionally with arguments"""
        raise NotImplementedError()

class Blocking(Threaded):
    """block until a task can be executed"""

    def __init__(self, *args, **kwargs):
        Threaded.__init__(self, *args, **kwargs)
        self._allocation_lock = thread.allocate_lock()

    def put(self, task, *args, **kwargs):
        """block until the task can be executed"""
        if self.nthreads == 0:
            self._handle_task(task, *args, **kwargs)
        else:
            if self.nthreads > 0: # block
                while 1: # allocate a thread
                    try:
                        self._allocation_lock.acquire()

                        if self.nactive.get() < self.nthreads:
                            self.nactive.transform(lambda n: n + 1)
                            break # releases lock
                    finally:
                        self._allocation_lock.release()
                    time.sleep(0.001) # since we're blocking, decrease usage
            thread.start_new_thread(self._handle_task,
                tuple([task] + list(args)), kwargs)

class Slaving(Threaded):
    """
    handle tasks among a finite (positive) number of slaves

    because threads are tough to kill,
    the only option is a graceful exit (use kill_all)
    """

    def __init__(self, nthreads = 1, *args, **kwargs):
        Threaded.__init__(self, nthreads, *args, **kwargs)
        self.alive = Synchronized(True)
        self._input_queue = Queue.Queue()

        if self.nthreads <= 0:
            raise ValueError("nthreads correlates to the number of slaves:" \
                " it must be positive")
        self.start() # starts the slaves

    def kill_all(self):
        """attempt to gracefully kill the slaves"""
        self.alive.set(False)

    def put(self, task, *args, **kwargs):
        """queue a task for execution"""
        self._input_queue.put(TaskInfo(task, None, *args, **kwargs))

    def _slave_loop(self):
        """handle tasks as they appear"""
        while self.alive.get():
            taskinfo = self._input_queue.get()
            self._handle_task(taskinfo.task, *taskinfo.args, **taskinfo.kwargs)

    def start(self):
        """set alive to True and start the slaves"""
        self.alive.set(True)
        i = 0

        while i < self.nthreads: # start the slaves
            thread.start_new_thread(self._slave_loop, ())
            i += 1

class Pipelining(Slaving):
    """pipeline iterable tasks among the slaves"""

    def __init__(self, nthreads = 1):
        Slaving.__init__(self, nthreads)
        self._handle_task = self._handle_iterable_task

    def _handle_iterable_task(self, iterable_task):
        """execute the task and enqueue any remaining steps"""
        try:
            iterable_task.next()
            self._input_queue.put(TaskInfo(iterable_task, None))
        except StopIteration:
            pass

    def put(self, iterable_task):
        """add an iterable task to the queue"""
        if not hasattr(iterable_task, "__iter__"):
            raise TypeError("iterable_task must be iterable")
        self._input_queue.put(TaskInfo(iterable_task, None))
