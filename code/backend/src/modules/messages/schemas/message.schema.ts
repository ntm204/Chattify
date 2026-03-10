import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum MessageType {
  TEXT = 'TEXT',
  IMAGE = 'IMAGE',
  VIDEO = 'VIDEO',
  FILE = 'FILE',
  VOICE = 'VOICE',
  SYSTEM_LOG = 'SYSTEM_LOG',
}

@Schema({ timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, collection: 'messages' })
export class Message extends Document {
  @Prop({ type: String, required: true, index: true })
  conversation_id: string; // Tham chiếu đến Conversation bằng UUID bên Postgres

  @Prop({ type: String, required: true })
  sender_id: string; // Tham chiếu đến User bằng UUID bên Postgres

  @Prop({ type: String, enum: MessageType, default: MessageType.TEXT })
  type: MessageType;

  @Prop({ type: String })
  content: string;

  @Prop({ type: [{ url: String, type: String, size: Number, width: Number, height: Number }] })
  media: any[];

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'Message' })
  reply_to: string; // ID của tin nhắn gốc nếu đây là reply

  @Prop({ type: String })
  forwarded_from: string; // ID tham chiếu đến User/Channel gốc

  @Prop({ type: [{ emoji: String, users: [String] }] })
  reactions: any[]; // Lưu mảng user UUID reaction theo từng emoji

  @Prop({ type: [String] })
  mentions: string[]; // Lưu mảng các UUID được tag

  @Prop({ type: Boolean, default: false })
  is_edited: boolean;

  @Prop({ type: Boolean, default: false })
  is_deleted: boolean;
  
  @Prop({ type: [{ user_id: String, read_at: Date }] })
  read_by: any[];
}

export const MessageSchema = SchemaFactory.createForClass(Message);
