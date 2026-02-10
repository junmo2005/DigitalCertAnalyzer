import threading
import queue
import time
import uuid
import json
from datetime import datetime

class TaskQueue:
    def __init__(self):
        self.tasks = {}
        self.results = {}
        self.lock = threading.Lock()
    
    def submit_task(self, task_func, *args, **kwargs):
        """提交任务并返回任务ID"""
        task_id = str(uuid.uuid4())
        
        def task_wrapper():
            try:
                result = task_func(*args, **kwargs)
                with self.lock:
                    self.results[task_id] = {
                        'status': 'completed',
                        'result': result,
                        'completed_at': datetime.now().isoformat()
                    }
            except Exception as e:
                with self.lock:
                    self.results[task_id] = {
                        'status': 'failed',
                        'error': str(e),
                        'completed_at': datetime.now().isoformat()
                    }
        
        # 启动后台线程
        thread = threading.Thread(target=task_wrapper)
        thread.daemon = True
        thread.start()
        
        with self.lock:
            self.tasks[task_id] = {
                'status': 'processing',
                'submitted_at': datetime.now().isoformat()
            }
        
        return task_id
    
    def get_task_status(self, task_id):
        """获取任务状态"""
        with self.lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.tasks:
                return self.tasks[task_id]
            else:
                return {'status': 'not_found'}

# 全局任务队列实例
task_queue = TaskQueue()