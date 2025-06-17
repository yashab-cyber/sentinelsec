import pymongo
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

class MongoHandler:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.db = None
        self.collections = {}
        self.logger = logging.getLogger(__name__)
        self.connect()
    
    def connect(self):
        """Connect to MongoDB"""
        try:
            mongo_config = self.config['mongodb']
            connection_string = f"mongodb://{mongo_config['host']}:{mongo_config['port']}/"
            self.client = pymongo.MongoClient(connection_string)
            self.db = self.client[mongo_config['database']]
            
            # Initialize collections
            for name, collection in mongo_config['collections'].items():
                self.collections[name] = self.db[collection]
            
            # Test connection
            self.client.admin.command('ismaster')
            self.logger.info("Connected to MongoDB successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    def insert_packet(self, packet_data: Dict[str, Any]) -> str:
        """Insert packet data into MongoDB"""
        try:
            packet_data['timestamp'] = datetime.utcnow()
            result = self.collections['packets'].insert_one(packet_data)
            return str(result.inserted_id)
        except Exception as e:
            self.logger.error(f"Failed to insert packet: {e}")
            return None
    
    def insert_alert(self, alert_data: Dict[str, Any]) -> str:
        """Insert alert data into MongoDB"""
        try:
            alert_data['timestamp'] = datetime.utcnow()
            result = self.collections['alerts'].insert_one(alert_data)
            return str(result.inserted_id)
        except Exception as e:
            self.logger.error(f"Failed to insert alert: {e}")
            return None
    
    def insert_anomaly(self, anomaly_data: Dict[str, Any]) -> str:
        """Insert anomaly data into MongoDB"""
        try:
            anomaly_data['timestamp'] = datetime.utcnow()
            result = self.collections['anomalies'].insert_one(anomaly_data)
            return str(result.inserted_id)
        except Exception as e:
            self.logger.error(f"Failed to insert anomaly: {e}")
            return None
    
    def insert_cve_data(self, cve_data: Dict[str, Any]) -> str:
        """Insert CVE data into MongoDB"""
        try:
            cve_data['cached_at'] = datetime.utcnow()
            # Use upsert to avoid duplicates
            filter_query = {'cve_id': cve_data.get('cve_id')}
            result = self.collections['cve_cache'].replace_one(
                filter_query, cve_data, upsert=True
            )
            return str(result.upserted_id) if result.upserted_id else "updated"
        except Exception as e:
            self.logger.error(f"Failed to insert CVE data: {e}")
            return None
    
    def get_packets(self, limit: int = 100, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Retrieve packets from MongoDB"""
        try:
            query = filters or {}
            cursor = self.collections['packets'].find(query).sort('timestamp', -1).limit(limit)
            return list(cursor)
        except Exception as e:
            self.logger.error(f"Failed to get packets: {e}")
            return []
    
    def get_alerts(self, limit: int = 100, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Retrieve alerts from MongoDB"""
        try:
            query = filters or {}
            cursor = self.collections['alerts'].find(query).sort('timestamp', -1).limit(limit)
            return list(cursor)
        except Exception as e:
            self.logger.error(f"Failed to get alerts: {e}")
            return []
    
    def get_anomalies(self, limit: int = 100, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Retrieve anomalies from MongoDB"""
        try:
            query = filters or {}
            cursor = self.collections['anomalies'].find(query).sort('timestamp', -1).limit(limit)
            return list(cursor)
        except Exception as e:
            self.logger.error(f"Failed to get anomalies: {e}")
            return []
    
    def get_cve_data(self, cve_id: str = None, software: str = None) -> List[Dict[str, Any]]:
        """Retrieve CVE data from cache"""
        try:
            query = {}
            if cve_id:
                query['cve_id'] = cve_id
            if software:
                query['$text'] = {'$search': software}
            
            cursor = self.collections['cve_cache'].find(query).sort('cached_at', -1)
            return list(cursor)
        except Exception as e:
            self.logger.error(f"Failed to get CVE data: {e}")
            return []
    
    def get_traffic_stats(self, time_range: int = 3600) -> Dict[str, Any]:
        """Get traffic statistics for the last time_range seconds"""
        try:
            start_time = datetime.utcnow() - timedelta(seconds=time_range)
            
            pipeline = [
                {'$match': {'timestamp': {'$gte': start_time}}},
                {'$group': {
                    '_id': {
                        'protocol': '$protocol',
                        'hour': {'$hour': '$timestamp'}
                    },
                    'count': {'$sum': 1}
                }}
            ]
            
            results = list(self.collections['packets'].aggregate(pipeline))
            
            stats = {
                'total_packets': len(results),
                'protocol_breakdown': {},
                'hourly_traffic': {}
            }
            
            for result in results:
                protocol = result['_id']['protocol']
                hour = result['_id']['hour']
                count = result['count']
                
                if protocol not in stats['protocol_breakdown']:
                    stats['protocol_breakdown'][protocol] = 0
                stats['protocol_breakdown'][protocol] += count
                
                if hour not in stats['hourly_traffic']:
                    stats['hourly_traffic'][hour] = 0
                stats['hourly_traffic'][hour] += count
            
            return stats
        except Exception as e:
            self.logger.error(f"Failed to get traffic stats: {e}")
            return {}
    
    def export_data(self, collection_name: str, output_file: str, format_type: str = 'json'):
        """Export collection data to file"""
        try:
            if collection_name not in self.collections:
                raise ValueError(f"Collection {collection_name} not found")
            
            data = list(self.collections[collection_name].find({}))
            
            # Convert ObjectId to string for JSON serialization
            for item in data:
                if '_id' in item:
                    item['_id'] = str(item['_id'])
                if 'timestamp' in item:
                    item['timestamp'] = item['timestamp'].isoformat()
            
            if format_type.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif format_type.lower() == 'csv':
                import pandas as pd
                df = pd.DataFrame(data)
                df.to_csv(output_file, index=False)
            
            self.logger.info(f"Exported {len(data)} records to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export data: {e}")
            return False
    
    def backup_database(self, backup_path: str):
        """Create a backup of the entire database"""
        try:
            import subprocess
            import os
            
            mongo_config = self.config['mongodb']
            dump_cmd = [
                'mongodump',
                '--host', f"{mongo_config['host']}:{mongo_config['port']}",
                '--db', mongo_config['database'],
                '--out', backup_path
            ]
            
            result = subprocess.run(dump_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info(f"Database backup created at {backup_path}")
                return True
            else:
                self.logger.error(f"Backup failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to backup database: {e}")
            return False
    
    def cleanup_old_data(self, days: int = 30):
        """Remove data older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            collections_to_clean = ['packets', 'alerts', 'anomalies']
            total_deleted = 0
            
            for collection_name in collections_to_clean:
                result = self.collections[collection_name].delete_many({
                    'timestamp': {'$lt': cutoff_date}
                })
                total_deleted += result.deleted_count
                self.logger.info(f"Deleted {result.deleted_count} old records from {collection_name}")
            
            self.logger.info(f"Total {total_deleted} old records deleted")
            return total_deleted
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
            return 0
    
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.logger.info("MongoDB connection closed")
