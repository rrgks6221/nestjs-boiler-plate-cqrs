import { TSID } from 'tsid-ts';

type Aggregate = 'User';

export abstract class DomainEvent<Payload = Record<string, any>> {
  id: string;
  aggregateId: string;
  abstract readonly aggregate: Aggregate;
  eventName: string;
  eventPayload: Payload;
  occurredAt: Date;

  constructor(aggregateId: string, eventPayload: Payload) {
    this.id = TSID.create().number.toString();
    this.aggregateId = aggregateId;
    this.eventName = this.constructor.name;
    this.eventPayload = eventPayload;
    this.occurredAt = new Date();
  }
}
