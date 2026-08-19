"""Provider-neutral seams for future GCP services; local mode has no cloud dependency."""
import os
from pathlib import Path
class LocalEventPublisher:
    status="LOCAL_SYNCHRONOUS"
    def publish(self,event):return {"accepted":True,"mode":self.status,"event_id":event.get("event_id")}
class PubSubPublisher(LocalEventPublisher):
    status="PUBSUB_CONFIGURED"
    def __init__(self,topic):self.topic=topic
    def publish(self,event):
        from google.cloud import pubsub_v1
        pubsub_v1.PublisherClient().publish(self.topic,repr(event).encode()).result();return {"accepted":True,"mode":self.status,"event_id":event.get("event_id")}
def event_publisher():
    topic=os.environ.get("GCP_PUBSUB_TOPIC")
    return PubSubPublisher(topic) if topic else LocalEventPublisher()
class LocalObjectStorage:
    status="LOCAL_STORAGE"
    def reference(self,name):return str(Path(os.environ.get("UPLOAD_FOLDER","shared_uploads"))/name)
class CloudStorage:
    status="CLOUD_STORAGE_CONFIGURED"
    def __init__(self,bucket):self.bucket=bucket
    def reference(self,name):return f"gs://{self.bucket}/{name}"
def object_storage():return CloudStorage(os.environ["GCP_STORAGE_BUCKET"]) if os.environ.get("GCP_STORAGE_BUCKET") else LocalObjectStorage()
