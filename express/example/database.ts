//a simple virtual database
export class Database<
  Model extends Record<string, string | number | boolean | null>
> {
  //internal data store
  private data: Model[] = [];

  constructor() {}

  //find one item
  public findOne<Key extends keyof Model, Value extends Model[Key]>(
    key: Key,
    value: Value
  ): Model | null {
    const item = this.data.find((item) => item[key] === value);
    return item || null;
  }

  //store one item
  public storeOne(item: Model) {
    this.data.push(item);
  }

  //delete one item
  public deleteOne<Key extends keyof Model, Value extends Model[Key]>(
    key: Key,
    value: Value
  ) {
    this.data.splice(
      this.data.findIndex((item) => item[key] === value),
      1
    );
  }

  //check if item exists
  public exists<Key extends keyof Model, Value extends Model[Key]>(
    key: Key,
    value: Value
  ): boolean {
    return !!this.findOne(key, value);
  }

  //return total item count
  public items(): number {
    return this.data.length;
  }
}
