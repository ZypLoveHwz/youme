#-*- coding:utf-8 -*-
#!/usr/bin/env python

import traceback
import time
import elasticsearch
import json
import mysql.connector
import datetime
import redis
import ipaddr
import re
from v2 import celery

class ELKLoop(object):

    def __init__(self):
        self.job_list = []
        self.server_jobs = []
        self.vm_jobs = []
        self.docker_jobs = []
        self.repository_jobs = []
        self.other_jobs = []
        self.log_store = 10
        self.invade_store = 10
        self.back_wait_seconds = 100 # wait for high exp vm to backup docker container,seconds
        self.action_container_id_history = []
        self.shutdown_docker_id_list = set()
        self.redis_server_info = {"host": "1.1.1.2",
                                  "port": 6379,
                                  "db": 0,
                                  "passwd": "redis_config_honeyD",
                                  "table_name": "HoneyPot",
                                  "ip_local_db": 2}
        self.elk_server_info = {"host": "1.1.1.4",
                                "port": 9200,
                                }
        self.mysql_server_info = {"host":"1.1.1.8",
                                  "user":"honey",
                                  "passwd":"1q2w3e4r",
                                  "db":"HoneyDesign"}
    
    
    def getConn(self):
        try:
            conn = mysql.connector.connect(user=self.mysql_server_info['user'],
                                           passwd=self.mysql_server_info['passwd'],
                                            host=self.mysql_server_info['host'],
                                            db=self.mysql_server_info['db'])
            return conn
        except:
            traceback.print_exc()
    
    def getRedisConn(self):
        redis_handler = None
        try:
            redis_handler = redis.StrictRedis(host=self.redis_server_info['host'],
                              port=self.redis_server_info['port'],
                              db=self.redis_server_info['db']
                              )
        except:
            pass
        finally:
            return redis_handler
            
    def getIpLocalRedisConn(self):
        redis_handler = None
        try:
            redis_handler = redis.StrictRedis(host=self.redis_server_info['host'],
                              port=self.redis_server_info['port'],
                              db=self.redis_server_info['ip_local_db']
                              )
        except:
            pass
        finally:
            return redis_handler
 
    def Sleep(self):
        time.sleep(10)
    
    def trimLog(self, data):
        trimed_log = {}
        _id = None
        try:
            if data.has_key('_source'):
                log_content = data['_source']['message']
                dest = data['_source']['message']
                source = None
                try:
                    source = log_content.split('- -')[0].strip()
                    if source == "::1":
                        source = "127.0.0.1"
                except:
                    source = re.findall('\d+\.\d+\.\d+\.\d+',log_content)[0]
                ipaddr.IPAddress(source)
                time_stamp = data['_source']['@timestamp']
                action = log_content.split('] "')[1].strip() or "Can't Trace Action!"
                trimed_log = {"source":source,
                              "dest":dest,
                              "timestamp":time_stamp,
                              "action":action}
                _id = data['_id']
        except:
            pass
        finally:
            return (_id,trimed_log)
    
    def searchWarnningContext(self,source=None,timestamp=None,warnning_id=None,local_storage=None):
        try:
            es_handler = elasticsearch.Elasticsearch(host="1.1.1.4", port=9200)
            if source and timestamp and warnning_id and local_storage:
                query = {
                          "query": {
                            "bool": {
                              "must": [
                                {
                                  "range": {
                                    "@timestamp": {
                                      "lte": timestamp
                                    }
                                  }
                                },
                                {
                                  "fuzzy": {
                                    "message": {
                                      "value": source,
                                      "min_similarity": "1"
                                    }
                                  }
                                },
                                {
                                 "prefix": {
                                    "source": local_storage
                                    }
                                }
                              ],
                              "must_not": [],
                              "should": []
                            }
                          },
                          "from": 0,
                          "size": 50,
                          "sort": [],
                          "aggs": {}
                        }
                result = es_handler.search(index="filebeat-*", body=query)['hits']['hits']
                warnning_data = [x["_source"]['message'] for x in result]
                if warnning_data:
                    redis_handler = self.getRedisConn()
                    alarm_lists = json.dumps(warnning_data)
                    redis_handler.hset("WarnningData",warnning_id,alarm_lists)
        except:
            traceback.print_exc()
    
    def trimWarnning(self,warnning_data=None):
        # warnning_data.append((data,host_ip,payload))
        """
        @param warnning_data: list -->tupal [(data,host_ip,port,payload,local_storage),(data,host_ip,port,payload,local_storage)]
        @ attention: 
            1. add message to warnning data
            2. search context of this warnning and save to redis
        """
        conn = self.getConn()
        cursor = conn.cursor()
        try:
            # get all uuid
            cursor.execute('select uuid from log_invade')
            res = cursor.fetchall()
            uuid_list = [x[0] for x in res]
            for data in warnning_data:
                warn_log,host_ip,port,payload,local_storage = data
                _message = warn_log["_source"]['message']
                _source = warn_log["_source"]['message'].split(" - -")[0]
                if not _source:
                    continue
                _id = warn_log['_id']
                if _id in uuid_list:
                    continue
                _target = host_ip
                if _source == "::1":
                    _source = "127.0.0.1"
                try:
                    ipaddr.IPAddress(_source)
                except:
                    try:
                        ip_list = re.findall('\d+\.\d+\.\d+\.\d+',warn_log["_source"]['message'])
                        if len(ip_list) > 1:
                            _source = str(ip_list)
                        else:
                            _source = ip_list.pop()
                    except:
                        _source = "check sid=>"+_id
                _target = _target+":"+port
                _payload = payload
                _record_time = warn_log["_source"]["@timestamp"]
                # _record_time=datetime.strptime(_record_time.split('.')[0],"%Y-%m-%dT%H:%M:%S")
                _log_source = warn_log['_source']['source']
                cursor.execute("""insert into log_invade(uuid,origin_ip,target_ip,
                payload,check_status,record_time,log_source,message) values(%s,%s,%s,%s,"UNCHECK",%s,%s,%s) """,(_id,_source,_target,_payload,_record_time,_log_source,_message,))
                conn.commit()
                self.searchWarnningContext(source=_source,timestamp=_record_time,warnning_id=_id,local_storage=local_storage)
        except:
            traceback.print_exc()
        finally:
            conn.commit()

    def setLogs(self):
        try:
            time_stamp = None
            conn = self.getConn()
            cursor = conn.cursor()
            get_recent_timestamp = "select log_update_datetime from config_update_log limit 1"
            cursor.execute(get_recent_timestamp)
            t_data = cursor.fetchone()
            if t_data:
                time_stamp = t_data[0]
            else:
                cursor.execute('insert into config_update_log(log_update_datetime) values("")')
                conn.commit()
            # search 
            es_handler = elasticsearch.Elasticsearch(host="1.1.1.4", port=9200)
            query = {
                 "query":{
                          "bool":{
                                  "must":[
                                          {"match_all":{}}
                                          ],
                                  "filter":{
                                            "range":{
                                                     "@timestamp":{"gt":time_stamp}
                                                     }
                                            }
                                  }
                          },
                "size":1000,
                "sort":{"@timestamp":{"order":"desc"}},
                 }
            
            result = es_handler.search(index="filebeat-*", body=query)['hits']['hits']
            if result:
                # get last data and make sure the timestamp
                last_one = result[0]
                time_stamp = last_one['_source']['@timestamp']
                cursor.execute("update config_update_log set log_update_datetime='%s'"%time_stamp)
                conn.commit()
                # for circle and push data into redis
                try:
                    redis_handler = self.getRedisConn()
                    iplocalredis_handler = self.getIpLocalRedisConn()
                    for data in result:
                        _id,trimed_log = self.trimLog(data)
                        if _id:
                            redis_data = json.dumps(trimed_log)
                            redis_handler.hset(self.redis_server_info['table_name'],
                                               _id,
                                               redis_data)
                            iplocalredis_handler.lpush(trimed_log['source'],trimed_log['timestamp'])
                            
                except:
                    pass
        except:
            traceback.print_exc()

    def setWarnnings(self):
        """
        the first data's time_stamp is the newest timestamp,time_stamp is a utf timestamp string, for check exist def a sort string.
        """
        warnning_data = []
        time_stamp = None
        last_string = 0
        last_time_stamp = None
        try:
            conn = self.getConn()
            cursor = conn.cursor()
            get_recent_timestamp = "select warnning_update_datetime from config_update_log limit 1"
            cursor.execute(get_recent_timestamp)
            time_stamp = cursor.fetchone()[0]
            if not time_stamp:
                time_stamp = None
                cursor.execute('update config_update_log set warnning_update_datetime=""')
                conn.commit()
            
            cursor.execute('select id,ip from group_vm')
            host_info  = cursor.fetchall()
            
            # connect to es
            es_handler = elasticsearch.Elasticsearch(host="1.1.1.4", port=9200)
            # get running containers
            cursor.execute("select payload,origin_payload,map_port,local_storage,docker_name,docker_id,docker_belong_vm from group_local_docker where docker_status='RUNNING'")
            res = cursor.fetchall()
            docker_info = [x for x in res]
            if docker_info:
                for docker_data in docker_info:
                    payload_list =json.loads(docker_data[0])+json.loads(docker_data[1])
                    map_port,local_storage,docker_name,docker_id,docker_belong_vm = docker_data[2:]
                    port = json.loads(map_port).values()[0]
                    host_ip = [ip[1] for ip in host_info if ip[0]==docker_belong_vm][0]
                    port = str(port)
                    for payload in payload_list: # word phrase
                        query = None
                        # search for a word
                        query_singleword = {
                                          "query": {
                                            "bool": {
                                              "filter": {
                                                "range": {
                                                  "@timestamp": {
                                                    "gt": time_stamp
                                                  }
                                                }
                                              },
                                              "must": [
                                                {
                                                  "fuzzy": {
                                                    "message": {
                                                      "value": payload,
                                                      "min_similarity": "1"
                                                    }
                                                  }
                                                }
                                              ],
                                              "must_not": [],
                                              "should": []
                                            }
                                          },
                                          "from": 0,
                                          "size": 1000,
                                          "sort": [
                                                   {
                                                      "@timestamp": {
                                                        "order": "desc",
                                                        "ignore_unmapped": True
                                                      }
                                                    }
                                                   ],
                                          "aggs": {}
                                        }
                        
                        # search for phrase
                        query_phrase = {
                                      "query": {
                                        "bool": {
                                          "filter": {
                                            "range": {
                                              "@timestamp": {
                                                "gt": time_stamp
                                              }
                                            }
                                          },
                                          "must": [
                                            {
                                              "match": {
                                                "message": {
                                                  "query": payload,
                                                  "type": "phrase",
                                                }
                                              }
                                            }
                                          ],
                                          "must_not": [],
                                          "should": []
                                        }
                                      },
                                      "from": 0,
                                      "size": 1000,
                                      "sort": [{
                                              "@timestamp": {
                                                "order": "desc",
                                                "ignore_unmapped": True
                                              }
                                            }
                                            ],
                                      "aggs": {}
                                    }
                        # search phrase not support sort
                        if payload.find(' ')>0:
                            query = query_phrase
                        else:
                            query = query_singleword
                        try:
                            res_search_result = es_handler.search(index="filebeat-*", body=query)['hits']['hits']
                            if res_search_result:
                                if docker_belong_vm == 3 and (not docker_id in self.shutdown_docker_id_list):
                                    self.shutdown_docker_id_list.add(docker_id)
                                    self.backupDocker(docker_id=docker_id,
                                                      docker_name=docker_name)
                                    self.shutdownDocker(docker_id=docker_id,
                                                        docker_name=docker_name,
                                                        vm_id=docker_belong_vm)
                                if res_search_result[0]["sort"][0] > last_string:
                                    last_string = res_search_result[0]['sort'][0]
                                    last_time_stamp = res_search_result[0]['_source']['@timestamp']
                                for data in res_search_result:
                                    if local_storage in data['_source']['source']:
                                        warnning_data.append((data,host_ip,port,payload,local_storage))
                        except:
                            traceback.print_exc()
            try:
                # warnning_update_time = datetime.datetime.now()
                if last_time_stamp:
                    cursor.execute("update config_update_log set warnning_update_datetime='%s'"%last_time_stamp)
                    conn.commit()
            except:
                pass
            self.trimWarnning(warnning_data=warnning_data)

        except:
            pass
                
    def getLogConfig(self):
        try:
            conn = self.getConn()
            cursor = conn.cursor()
            get_all_logs = """select log_store,invade_store from config_log"""
            cursor.execute(get_all_logs)
            res = cursor.fetchone()
            if res:
                self.log_store, self.invade_store = res
        except:
            traceback.print_exc()
            
    def backupDocker(self,docker_id=None,docker_name=None):
        if docker_id and docker_name:
            try:
                file_timestamp = str(time.time())
                queue_name = "ExpHighBackup"
                docker_orgin = docker_name
                docker_name = docker_name.replace(':',"_") #if file_name has ":", cannot push to rep locally
                file_name = (queue_name+"_"+docker_id+"_"+docker_name+"_"+file_timestamp).lower()
                data = {'docker_id':docker_id,
                    'filename':file_name
                    }
                conn = self.getConn()
                cursor = conn.cursor()
                cursor.execute('insert into backUpImages(docker_name,vm_id,docker_id,create_time,reason,file_tag) values("%s",3,"%s","%s","Attack Alarm","%s")'%(docker_orgin,docker_id,datetime.datetime.now(),file_name))
                conn.commit()
                handler = celery.ExpHighBackup.apply_async((data,),queue=queue_name)
                handler.wait(timeout=self.back_wait_seconds)
            except:
                traceback.print_exc()
            
    def shutdownDocker(self, docker_id, docker_name, vm_id):
        try:
            conn = self.getConn()
            cursor = conn.cursor()
            cursor.execute("update group_local_docker set docker_status='DELETEING' where docker_id=%s",(docker_id,))
            cursor.execute("""insert into job_list_v2(type,settle_status,job_time,operation,vm_id,docker_id,docker_name) values('docker','NOT_SETTLE',%s,'delete',%s,%s,%s)""",(datetime.datetime.now(),vm_id,docker_id,docker_name))
            conn.commit()
        except:
            pass

    def main(self):
        while True:
            self.getLogConfig()
            self.setLogs()
            self.setWarnnings()
            self.Sleep()
   
print "ELK Looping ~~~"
a = ELKLoop()
a.main()




#{"query":{"bool":{"filter":{"range":{"@timestamp": {"gt": time_stamp}}},"must":[{"match":{"message":{"query":payload,"type": "phrase"}}}],"must_not":[],"should":[]}},"from":0,"size":1000,"sort":[],"aggs":{}}