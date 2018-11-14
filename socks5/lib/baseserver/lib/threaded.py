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
__package__ = __name__

import Queue
import thread
import time

__doc__ = "threaded multitasking"

class FuncInfo:
    """information about a function call"""

    def __init__(self, func, output, *args, **kwargs):
        self.args = args
        self.func = func
        self.kwargs = kwargs
        self.output = output

class IterableTask:
    """a task with discrete steps"""
    
    def __init__(self):
        pass

    def __call__(self):
        for step in self:
            pass

    def __iter__(self):
        return self

    def next(self):
        """perform the next step (usually without a return value)"""
        raise StopIteration()

class Synchronized:
    def __init__(self, value = None):
        self._lock = thread.allocate_lock()
        self.value = value

    def get(self):
        with self._lock:
            return self.value

    def modify(self, func = lambda v: v):
        """modify the value via a function"""
        with self._lock:
            self.value = func(self.value)

    def set(self, value = None):
        with self._lock:
            self.value = value

class Threaded(Queue.Queue):
    """
    allocates up to N additional threads for function calls (w/ blocking)
    or run function calls in the current thread if nthreads == 0

    when nthreads == 0, tasks are executed in the calling thread
    when nthreads < 0, tasks are always executed in a new thread

    when queue_output evaluates to True, function call information is
    queued into the current instance (a Queue) as FuncInfo instances
    """

    def __init__(self, nthreads = -1, queue_output = False):
        Queue.Queue.__init__(self)
        self._allocation_lock = thread.allocate_lock()
        self.nactive_threads = Synchronized(0)
        self.nthreads = nthreads
        self.queue_output = queue_output

    def execute(self, func, *args, **kwargs):
        """block until thread allocation is possible"""
        if self.nthreads:
            if self.nthreads > 0:
                with self._allocation_lock: # block
                    while 1:
                        with self.nactive_threads._lock:
                            if self.nactive_threads.value < self.nthreads:
                                self.nactive_threads.value += 1
                                break
            # otherwise, self.nthreads < 0, so we don't block
            thread.start_new_thread(self._handle_thread,
                tuple([func] + list(args)), kwargs)
        else:
            with self._allocation_lock: # block
                self.nactive_threads.modify(lambda v: v + 1)
                self._handle_thread(func, *args, **kwargs)
    
    def _handle_thread(self, func, *args, **kwargs):
        """handle the current thread's execution"""
        try:
            output = func(*args, **kwargs)
        except Exception as output:
            pass

        if self.queue_output:
            Queue.Queue.put(self, FuncInfo(func, output, *args, **kwargs))

        if self.nthreads:
            self.nactive_threads.modify(lambda v: v - 1)

    def put(self, func, *args, **kwargs):
        """synonym for Threaded.execute"""
        self.execute(func, *args, **kwargs)

class Iterative(Threaded):
    """
    when nthreads > 0, distributes tasks between a set number of handlers

    otherwise, uses Threaded's default behavior
    """
    
    def __init__(self, nthreads = 1, queue_output = False, sleep = 0.001):
        Threaded.__init__(self, nthreads, queue_output)
        self.alive = Synchronized(True)
        self._input_queue = Queue.Queue()
        self.sleep = sleep
        
        if self.nthreads > 0:
            for n in range(self.nthreads):
                thread.start_new_thread(self._slave, ())
                self.nactive_threads.modify(lambda v: v + 1)

    def execute(self, func, *args, **kwargs):
        """add the task to the queue"""
        if self.nthreads > 0:
            self._input_queue.put(FuncInfo(func, None, *args, **kwargs))
        else: # use default behavior
            Threaded.execute(self, func, *args, **kwargs)
    
    def kill_all(self):
        """passively attempt to kill all the threads"""
        self.alive.set(False)

    def put(self, func, *args, **kwargs):
        """synonym for Iterative.execute"""
        self.execute(func, *args, **kwargs)

    def _slave(self):
        """continuously execute tasks"""
        while 1:
            if not self.alive.get():
                break
            funcinfo = None
            
            while not funcinfo:
                if not self.alive.get():
                    return
                
                try:
                    funcinfo = self._input_queue.get()
                except ValueError:
                    time.sleep(self.sleep)

            try:
                funcinfo.output = funcinfo.func(*funcinfo.args,
                    **funcinfo.kwargs)
            except Exception as funcinfo.output:
                pass

            if self.queue_output:
                Queue.Queue.put(self, funcinfo)

class Pipelining(Iterative):
    """
    pipeline iterable tasks;
    tasks must be iterable, preferably subclassing IterableTask
    
    this class continually requeues unfinished tasks
    """
    
    def __init__(self, *args, **kwargs):
        Iterative.__init__(self, *args, **kwargs)

    def execute(self, iterable_task):
        """accepts iterable tasks instead of functions"""
        if not hasattr(iterable_task, "__iter__"):
            raise TypeError("iterable_task must be iterable")
        Iterative.execute(self, lambda: self._wrap_iterable_task_next(
            iterable_task))

    def put(self, iterable_task):
        """synonym for Pipelining.execute"""
        self.execute(iterable_task)

    def _wrap_iterable_task_next(self, iterable_task):
        """execute then requeue if necessary"""
        try:
            retval = iterable_task.next()
        except StopIteration:
            return
        Iterative.execute(self, lambda: self._wrap_iterable_task_next(
            iterable_task))
        return retval
