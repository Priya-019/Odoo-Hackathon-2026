# models.py
"""
TransitOps — SQLAlchemy ORM Models
====================================

Defines the database tables for the TransitOps platform:

Phase 1:
    ┌──────────┐        ┌───────────┐        ┌────────────┐
    │   User   │        │  Vehicle  │        │   Driver   │
    │──────────│        │───────────│        │────────────│
    │ id (PK)  │        │ id (PK)   │        │ id (PK)    │
    │ email    │        │ reg_num   │        │ name       │
    │ pwd_hash │        │ model     │        │ license_no │
    │ role     │        │ type      │        │ category   │
    └──────────┘        │ capacity  │        │ expiry     │
                        │ odometer  │        │ contact    │
                        │ acq_cost  │        │ safety_scr │
                        │ status    │        │ status     │
                        └───────────┘        └────────────┘

Phase 2:
    ┌─────────────────────────┐
    │          Trip           │
    │─────────────────────────│
    │ id (PK)                 │
    │ trip_code (unique, auto)│
    │ source                  │
    │ destination             │
    │ vehicle_id (FK)  ───────┼──► vehicles.id
    │ driver_id  (FK)  ───────┼──► drivers.id
    │ cargo_weight             │
    │ planned_distance         │
    │ status (state machine)  │
    └─────────────────────────┘

All enum values are stored as VARCHAR in SQLite (no native ENUM type)
and validated by Pydantic at the API boundary.
"""

import enum

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import relationship

from database import Base


# ---------------------------------------------------------------------------
# Enum definitions
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    fleet_manager    = "Fleet Manager"
    driver           = "Driver"
    safety_officer   = "Safety Officer"
    financial_analyst = "Financial Analyst"


class VehicleStatus(str, enum.Enum):
    available = "Available"
    on_trip   = "On Trip"
    in_shop   = "In Shop"
    retired   = "Retired"


class DriverStatus(str, enum.Enum):
    available = "Available"
    on_trip   = "On Trip"
    off_duty  = "Off Duty"
    suspended = "Suspended"


class TripStatus(str, enum.Enum):
    draft      = "Draft"
    dispatched = "Dispatched"
    completed  = "Completed"
    cancelled  = "Cancelled"


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class User(Base):
    """Platform user — controls authentication and role-based access."""

    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    email         = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role          = Column(
        Enum(UserRole, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )


class Vehicle(Base):
    """Fleet vehicle — trackable asset assigned to trips."""

    __tablename__ = "vehicles"
    __table_args__ = (
        UniqueConstraint("registration_number", name="uq_vehicle_reg_num"),
    )

    id                  = Column(Integer, primary_key=True, index=True)
    registration_number = Column(String, unique=True, nullable=False, index=True)
    model_name          = Column(String,  nullable=True)
    vehicle_type        = Column(String,  nullable=True)
    max_load_capacity   = Column(Float,   nullable=True,  comment="kg")
    odometer            = Column(Float,   nullable=True,  comment="km")
    acquisition_cost    = Column(Float,   nullable=True,  comment="currency units")
    status              = Column(
        Enum(VehicleStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=VehicleStatus.available,
        server_default="Available",
    )

    # Back-references
    trips            = relationship("Trip",           back_populates="vehicle")
    maintenance_logs = relationship("MaintenanceLog", back_populates="vehicle")
    fuel_logs        = relationship("FuelLog",        back_populates="vehicle")
    expenses         = relationship("Expense",        back_populates="vehicle")


class Driver(Base):
    """Licensed driver — human resource assigned to fleet trips."""

    __tablename__ = "drivers"

    id                  = Column(Integer, primary_key=True, index=True)
    name                = Column(String, nullable=False)
    license_number      = Column(String, unique=True, nullable=True, index=True)
    license_category    = Column(String, nullable=True)
    license_expiry_date = Column(Date,   nullable=True)
    contact_number      = Column(String, nullable=True)
    safety_score        = Column(Float,  nullable=False, default=100.0)
    status              = Column(
        Enum(DriverStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=DriverStatus.available,
        server_default="Available",
    )

    # Back-reference: all trips assigned to this driver
    trips = relationship("Trip", back_populates="driver")


class Trip(Base):
    """Fleet trip — single dispatch unit managed by the TransitOps platform.

    Lifecycle state machine::

        Draft  ──► Dispatched  ──► Completed
          │
          └──────────────────────► Cancelled

    The ``trip_code`` is auto-generated after insert as 'TRIP-XXXX'.
    """

    __tablename__ = "trips"

    id               = Column(Integer, primary_key=True, index=True)
    trip_code        = Column(String, unique=True, nullable=True, index=True)
    source           = Column(String, nullable=False)
    destination      = Column(String, nullable=False)
    vehicle_id       = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    driver_id        = Column(Integer, ForeignKey("drivers.id"), nullable=False)
    cargo_weight     = Column(Float, nullable=False, comment="kg")
    planned_distance = Column(Float, nullable=False, comment="km")
    status           = Column(
        Enum(TripStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=TripStatus.draft,
        server_default="Draft",
    )

    # Relationships
    vehicle = relationship("Vehicle", back_populates="trips")
    driver  = relationship("Driver",  back_populates="trips")


class MaintenanceLog(Base):
    """Vehicle maintenance / service record.

    When a maintenance log is opened (``is_open=True``), the linked vehicle
    is automatically moved to 'In Shop' status.  Closing the log restores
    the vehicle to 'Available' (unless it was 'Retired').
    """

    __tablename__ = "maintenance_logs"

    id           = Column(Integer, primary_key=True, index=True)
    vehicle_id   = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    service_type = Column(String, nullable=False)
    open_date    = Column(Date, nullable=False)
    close_date   = Column(Date, nullable=True)
    cost         = Column(Float, nullable=False, default=0.0)
    is_open      = Column(Boolean, nullable=False, default=True)

    # Relationship
    vehicle = relationship("Vehicle", back_populates="maintenance_logs")


class FuelLog(Base):
    """Per-vehicle fuel fill-up record."""

    __tablename__ = "fuel_logs"

    id         = Column(Integer, primary_key=True, index=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    liters     = Column(Float, nullable=False)
    cost       = Column(Float, nullable=False)
    date       = Column(Date, nullable=False)

    # Relationship
    vehicle = relationship("Vehicle", back_populates="fuel_logs")


class Expense(Base):
    """Miscellaneous vehicle expense (tolls, insurance, etc.)."""

    __tablename__ = "expenses"

    id           = Column(Integer, primary_key=True, index=True)
    vehicle_id   = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    expense_type = Column(String, nullable=False)
    amount       = Column(Float, nullable=False)
    date         = Column(Date, nullable=False)

    # Relationship
    vehicle = relationship("Vehicle", back_populates="expenses")


# ---------------------------------------------------------------------------
# Auto-generate trip_code after insert  (e.g. TRIP-0001, TRIP-0002, …)
# ---------------------------------------------------------------------------

@event.listens_for(Trip, "after_insert")
def _generate_trip_code(mapper, connection, target):
    """Set trip_code = 'TRIP-{id:04d}' immediately after the row is inserted."""
    connection.execute(
        Trip.__table__.update()
        .where(Trip.__table__.c.id == target.id)
        .values(trip_code=f"TRIP-{target.id:04d}")
    )
