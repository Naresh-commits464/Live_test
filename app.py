from dataclasses import dataclass

@dataclass
class Order:
    item: str
    quantity: int
    unit_price: float

def total(order: Order) -> float:
    return order.quantity * order.unit_price

if __name__ == "__main__":
    order = Order("notebook", 2, 4.50)
    print({"item": order.item, "total": total(order)})
