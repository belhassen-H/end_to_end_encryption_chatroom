import pika
import json
def callback( ch , method , properties, body):
    print("[x] received ",body.decode("ascii"))


    ch.queue_declare(queue='certificate_request_queue')
    client_data = {
        "client_id": body.decode("ascii")
    }
 
    ch.basic_publish(exchange='',
                          routing_key='certificate_request_queue',
                          body=json.dumps(client_data))
    print(f"demande de certification a ete envoyer pour :", body.decode('ascii') )

def request_certificate():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    
    channel.queue_declare(queue='client_id')
    channel.basic_consume(queue='client_id',
                          auto_ack=True,
                          on_message_callback=callback)
    channel.start_consuming()
    return 0
 
if __name__ == "__main__":
    #client_id = input("donner login: ")
    request_certificate()
