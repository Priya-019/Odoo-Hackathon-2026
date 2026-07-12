# main.py
"""
TransitOps REST API — Phase 1, 2, 3 & 4
==========================================

Endpoints
---------
Auth
    POST  /api/auth/register   – Register a new user (hashed password)
    POST  /api/auth/login      – Validate credentials, return role + user ID

Vehicles
    GET   /api/vehicles        – List all fleet vehicles
    POST  /api/vehicles        – Register a new vehicle (400 on duplicate reg)

Drivers
    GET   /api/drivers         – List all drivers
    POST  /api/drivers         – Register a new driver

Trips (Phase 2)
    POST  /api/trips                     – Create a trip (Draft)
    GET   /api/trips                     – List all trips
    PATCH /api/trips/{trip_id}/dispatch   – Draft → Dispatched
    PATCH /api/trips/{trip_id}/complete   – Dispatched → Completed
    PATCH /api/trips/{trip_id}/cancel     – Draft/Dispatched → Cancelled

Maintenance, Fuel & Expenses (Phase 3)
    POST  /api/maintenance                    – Open maintenance log (vehicle → In Shop)
    PATCH /api/maintenance/{log_id}/close     – Close maintenance log (vehicle → Available)
    POST  /api/fuel                           – Log fuel fill-up
    POST  /api/expenses                       – Log miscellaneous expense
    GET   /api/vehicles/{vehicle_id}/total-cost – Aggregated operational cost

Dashboard & Reports (Phase 4)
    GET   /api/dashboard/kpis                 – Live operational KPIs
    GET   /api/reports/vehicles               – Financial report & ROI per vehicle
    GET   /api/reports/export-csv             – CSV export of the financial report

Run locally
-----------
    pip install fastapi uvicorn sqlalchemy pydantic[email]
    uvicorn main:app --reload --port 8000

Interactive docs available at:
    http://localhost:8000/docs   (Swagger UI)
    http://localhost:8000/redoc  (ReDoc)
"""

import csv
import datetime
import hashlib
import io
import os
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import orm_models as models
import schemas
from database import Base, engine, get_db
from services import validate_trip_dispatch

# ---------------------------------------------------------------------------
# Bootstrap — create all tables on startup if they don't exist
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# FastAPI application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="TransitOps API",
    description=(
        "Smart Transport Operations Platform — Phase 1, 2 & 3 REST API.\n\n"
        "Handles user authentication, fleet vehicles, drivers, trip lifecycle, "
        "maintenance logs, fuel tracking, expenses, and cost aggregation."
    ),
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — allow all origins during hackathon development
# Tighten ``allow_origins`` before any production deployment.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
# Utility helpers
# ===========================================================================

def _hash_password(plain: str) -> str:
    """Return a SHA-256 hex digest of the plain-text password.

    For a production system, replace with ``bcrypt`` or ``argon2``::

        import bcrypt
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
    """
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def _verify_password(plain: str, hashed: str) -> bool:
    """Compare a plain-text password against its stored hash."""
    return _hash_password(plain) == hashed


VALID_ROLES = {role.value for role in models.UserRole}
VALID_VEHICLE_STATUSES = {s.value for s in models.VehicleStatus}
VALID_DRIVER_STATUSES = {s.value for s in models.DriverStatus}


# ===========================================================================
# Health check
# ===========================================================================

@app.get("/", tags=["Health"])
def root():
    """Liveness check — confirms the API is running."""
    return {"status": "ok", "service": "TransitOps API", "version": "3.0.0"}


# ===========================================================================
# Auth endpoints
# ===========================================================================

@app.post(
    "/api/auth/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
    summary="Register a new platform user",
)
def register_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    """Create a new user account with a hashed password.

    - **email**: must be a valid e-mail address and globally unique.
    - **password**: stored as a SHA-256 hash (upgrade to bcrypt for prod).
    - **role**: must be one of ``Fleet Manager``, ``Driver``,
      ``Safety Officer``, ``Financial Analyst``.

    Returns the created user profile (password hash excluded).
    """
    # Validate role
    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{payload.role}'. Valid roles: {sorted(VALID_ROLES)}",
        )

    # Check for duplicate email
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A user with email '{payload.email}' already exists.",
        )

    user = models.User(
        email=payload.email,
        password_hash=_hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post(
    "/api/auth/login",
    response_model=schemas.LoginResponse,
    tags=["Auth"],
    summary="Authenticate and retrieve user role",
)
def login_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    """Validate credentials and return the user's role and ID.

    For the hackathon demo this is session-less (no JWT issued).
    The ``role`` in the response drives frontend RBAC rendering.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not _verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    return schemas.LoginResponse(
        message="Login successful",
        user_id=user.id,
        role=user.role,
    )


# ===========================================================================
# Vehicle endpoints
# ===========================================================================

@app.get(
    "/api/vehicles",
    response_model=List[schemas.VehicleResponse],
    tags=["Vehicles"],
    summary="List all fleet vehicles",
)
def list_vehicles(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Return a paginated list of all registered fleet vehicles."""
    return db.query(models.Vehicle).offset(skip).limit(limit).all()


@app.post(
    "/api/vehicles",
    response_model=schemas.VehicleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Vehicles"],
    summary="Register a new fleet vehicle",
)
def create_vehicle(
    payload: schemas.VehicleCreate,
    db: Session = Depends(get_db),
):
    """Register a new vehicle in the fleet.

    - **registration_number**: must be globally unique — raises **HTTP 400**
      if a vehicle with the same plate already exists.
    - **status**: defaults to ``Available`` if omitted.
    """
    # Validate status if provided
    if payload.status and payload.status not in VALID_VEHICLE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{payload.status}'. Valid: {sorted(VALID_VEHICLE_STATUSES)}",
        )

    # Check for duplicate registration number
    duplicate = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.registration_number == payload.registration_number)
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Vehicle with registration number '{payload.registration_number}' "
                "already exists."
            ),
        )

    vehicle = models.Vehicle(**payload.model_dump() if hasattr(payload, "model_dump") else payload.dict())
    db.add(vehicle)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Duplicate registration number '{payload.registration_number}'.",
        )
    db.refresh(vehicle)
    return vehicle


# ===========================================================================
# Driver endpoints
# ===========================================================================

@app.get(
    "/api/drivers",
    response_model=List[schemas.DriverResponse],
    tags=["Drivers"],
    summary="List all registered drivers",
)
def list_drivers(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Return a paginated list of all drivers in the system."""
    return db.query(models.Driver).offset(skip).limit(limit).all()


@app.post(
    "/api/drivers",
    response_model=schemas.DriverResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Drivers"],
    summary="Register a new driver",
)
def create_driver(
    payload: schemas.DriverCreate,
    db: Session = Depends(get_db),
):
    """Register a new driver in the system.

    - **name**: required — the driver's full legal name.
    - **license_number**: must be unique if provided.
    - **safety_score**: defaults to ``100.0`` (perfect score on joining).
    - **status**: defaults to ``Available``.
    """
    # Validate status if provided
    if payload.status and payload.status not in VALID_DRIVER_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{payload.status}'. Valid: {sorted(VALID_DRIVER_STATUSES)}",
        )

    driver = models.Driver(**payload.model_dump() if hasattr(payload, "model_dump") else payload.dict())
    db.add(driver)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Duplicate license number '{payload.license_number}'.",
        )
    db.refresh(driver)
    return driver


# ===========================================================================
# Trip endpoints (Phase 2)
# ===========================================================================

@app.post(
    "/api/trips",
    response_model=schemas.TripResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Trips"],
    summary="Create a new trip (Draft)",
)
def create_trip(
    payload: schemas.TripCreate,
    db: Session = Depends(get_db),
):
    """Create a new trip in **Draft** status.

    Before persisting, the business rule engine validates:

    1. **Capacity** — cargo_weight ≤ vehicle.max_load_capacity
    2. **Driver compliance** — not suspended, licence not expired
    3. **Availability** — vehicle and driver must both be 'Available'
    """
    # Run the rule engine
    validate_trip_dispatch(
        db=db,
        vehicle_id=payload.vehicle_id,
        driver_id=payload.driver_id,
        cargo_weight=payload.cargo_weight,
    )

    trip = models.Trip(
        source=payload.source,
        destination=payload.destination,
        vehicle_id=payload.vehicle_id,
        driver_id=payload.driver_id,
        cargo_weight=payload.cargo_weight,
        planned_distance=payload.planned_distance,
        status=models.TripStatus.draft.value,
    )
    db.add(trip)
    db.commit()
    db.refresh(trip)
    return trip


@app.get(
    "/api/trips",
    response_model=List[schemas.TripResponse],
    tags=["Trips"],
    summary="List all trips",
)
def list_trips(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Return a paginated list of all trips in the system."""
    return db.query(models.Trip).offset(skip).limit(limit).all()


@app.patch(
    "/api/trips/{trip_id}/dispatch",
    response_model=schemas.TripResponse,
    tags=["Trips"],
    summary="Dispatch a trip (Draft → Dispatched)",
)
def dispatch_trip(
    trip_id: int,
    db: Session = Depends(get_db),
):
    """Transition a trip from **Draft** to **Dispatched**.

    Re-runs the full business rule engine to confirm the vehicle and driver
    are still eligible, then atomically:

    - Sets ``trip.status = 'Dispatched'``
    - Sets ``vehicle.status = 'On Trip'``
    - Sets ``driver.status = 'On Trip'``
    """
    trip = db.query(models.Trip).filter(models.Trip.id == trip_id).first()
    if not trip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trip with id {trip_id} not found.",
        )

    if trip.status != models.TripStatus.draft.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Trip '{trip.trip_code}' cannot be dispatched — "
                f"current status is '{trip.status}' (must be 'Draft')."
            ),
        )

    # Re-validate business rules (vehicle/driver may have changed since creation)
    vehicle, driver = validate_trip_dispatch(
        db=db,
        vehicle_id=trip.vehicle_id,
        driver_id=trip.driver_id,
        cargo_weight=trip.cargo_weight,
    )

    # --- Atomic state transition + automated status sync ---------------------
    trip.status    = models.TripStatus.dispatched.value
    vehicle.status = models.VehicleStatus.on_trip.value
    driver.status  = models.DriverStatus.on_trip.value

    db.commit()
    db.refresh(trip)
    return trip


@app.patch(
    "/api/trips/{trip_id}/complete",
    response_model=schemas.TripResponse,
    tags=["Trips"],
    summary="Complete a trip (Dispatched → Completed)",
)
def complete_trip(
    trip_id: int,
    db: Session = Depends(get_db),
):
    """Transition a trip from **Dispatched** to **Completed**.

    Atomically:

    - Sets ``trip.status = 'Completed'``
    - Restores ``vehicle.status = 'Available'``
    - Restores ``driver.status = 'Available'``
    """
    trip = db.query(models.Trip).filter(models.Trip.id == trip_id).first()
    if not trip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trip with id {trip_id} not found.",
        )

    if trip.status != models.TripStatus.dispatched.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Trip '{trip.trip_code}' cannot be completed — "
                f"current status is '{trip.status}' (must be 'Dispatched')."
            ),
        )

    vehicle = db.query(models.Vehicle).filter(models.Vehicle.id == trip.vehicle_id).first()
    driver  = db.query(models.Driver).filter(models.Driver.id == trip.driver_id).first()

    # --- Atomic state transition + automated status sync ---------------------
    trip.status    = models.TripStatus.completed.value
    vehicle.status = models.VehicleStatus.available.value
    driver.status  = models.DriverStatus.available.value

    db.commit()
    db.refresh(trip)
    return trip


@app.patch(
    "/api/trips/{trip_id}/cancel",
    response_model=schemas.TripResponse,
    tags=["Trips"],
    summary="Cancel a trip (Draft/Dispatched → Cancelled)",
)
def cancel_trip(
    trip_id: int,
    db: Session = Depends(get_db),
):
    """Cancel a trip from **Draft** or **Dispatched** state.

    Atomically:

    - Sets ``trip.status = 'Cancelled'``
    - Restores ``vehicle.status = 'Available'``
    - Restores ``driver.status = 'Available'``
    """
    trip = db.query(models.Trip).filter(models.Trip.id == trip_id).first()
    if not trip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trip with id {trip_id} not found.",
        )

    if trip.status not in (
        models.TripStatus.draft.value,
        models.TripStatus.dispatched.value,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Trip '{trip.trip_code}' cannot be cancelled — "
                f"current status is '{trip.status}' "
                "(must be 'Draft' or 'Dispatched')."
            ),
        )

    vehicle = db.query(models.Vehicle).filter(models.Vehicle.id == trip.vehicle_id).first()
    driver  = db.query(models.Driver).filter(models.Driver.id == trip.driver_id).first()

    # --- Atomic state transition + automated status sync ---------------------
    trip.status    = models.TripStatus.cancelled.value
    vehicle.status = models.VehicleStatus.available.value
    driver.status  = models.DriverStatus.available.value

    db.commit()
    db.refresh(trip)
    return trip


# ===========================================================================
# Maintenance endpoints (Phase 3)
# ===========================================================================

@app.post(
    "/api/maintenance",
    response_model=schemas.MaintenanceLogResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Maintenance"],
    summary="Open a new maintenance log (vehicle -> In Shop)",
)
def create_maintenance_log(
    payload: schemas.MaintenanceLogCreate,
    db: Session = Depends(get_db),
):
    """Open a maintenance log for a vehicle.

    **Automated Sync**: sets ``vehicle.status = 'In Shop'`` so the vehicle
    is removed from the dispatch pool until the log is closed.
    """
    vehicle = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.id == payload.vehicle_id)
        .first()
    )
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vehicle with id {payload.vehicle_id} not found.",
        )

    log = models.MaintenanceLog(
        vehicle_id=payload.vehicle_id,
        service_type=payload.service_type,
        open_date=payload.open_date,
        cost=payload.cost or 0.0,
        is_open=True,
    )
    db.add(log)

    # Automated status sync: vehicle -> In Shop
    vehicle.status = models.VehicleStatus.in_shop.value

    db.commit()
    db.refresh(log)
    return log


@app.patch(
    "/api/maintenance/{log_id}/close",
    response_model=schemas.MaintenanceLogResponse,
    tags=["Maintenance"],
    summary="Close a maintenance log (vehicle -> Available)",
)
def close_maintenance_log(
    log_id: int,
    payload: schemas.MaintenanceLogClose,
    db: Session = Depends(get_db),
):
    """Close an active maintenance log.

    Sets ``close_date``, ``is_open = False``, and records the final ``cost``.

    **Automated Sync**: restores ``vehicle.status = 'Available'`` unless the
    vehicle was already marked as ``'Retired'``.
    """
    log = (
        db.query(models.MaintenanceLog)
        .filter(models.MaintenanceLog.id == log_id)
        .first()
    )
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Maintenance log with id {log_id} not found.",
        )

    if not log.is_open:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maintenance log {log_id} is already closed.",
        )

    log.close_date = payload.close_date
    log.cost       = payload.cost
    log.is_open    = False

    # Automated status sync: vehicle -> Available (unless Retired)
    vehicle = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.id == log.vehicle_id)
        .first()
    )
    if vehicle and vehicle.status != models.VehicleStatus.retired.value:
        vehicle.status = models.VehicleStatus.available.value

    db.commit()
    db.refresh(log)
    return log


# ===========================================================================
# Fuel Log endpoints (Phase 3)
# ===========================================================================

@app.post(
    "/api/fuel",
    response_model=schemas.FuelLogResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Fuel"],
    summary="Log a fuel fill-up for a vehicle",
)
def create_fuel_log(
    payload: schemas.FuelLogCreate,
    db: Session = Depends(get_db),
):
    """Record fuel consumption (liters, cost, date) against a vehicle."""
    vehicle = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.id == payload.vehicle_id)
        .first()
    )
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vehicle with id {payload.vehicle_id} not found.",
        )

    fuel = models.FuelLog(
        vehicle_id=payload.vehicle_id,
        liters=payload.liters,
        cost=payload.cost,
        date=payload.date,
    )
    db.add(fuel)
    db.commit()
    db.refresh(fuel)
    return fuel


# ===========================================================================
# Expense endpoints (Phase 3)
# ===========================================================================

@app.post(
    "/api/expenses",
    response_model=schemas.ExpenseResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Expenses"],
    summary="Log a miscellaneous expense for a vehicle",
)
def create_expense(
    payload: schemas.ExpenseCreate,
    db: Session = Depends(get_db),
):
    """Record a miscellaneous expense (toll, insurance, etc.) for a vehicle."""
    vehicle = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.id == payload.vehicle_id)
        .first()
    )
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vehicle with id {payload.vehicle_id} not found.",
        )

    expense = models.Expense(
        vehicle_id=payload.vehicle_id,
        expense_type=payload.expense_type,
        amount=payload.amount,
        date=payload.date,
    )
    db.add(expense)
    db.commit()
    db.refresh(expense)
    return expense


# ===========================================================================
# Cost aggregation (Phase 3)
# ===========================================================================

@app.get(
    "/api/vehicles/{vehicle_id}/total-cost",
    response_model=schemas.VehicleTotalCostResponse,
    tags=["Cost Aggregation"],
    summary="Get total operational cost for a vehicle",
)
def get_vehicle_total_cost(
    vehicle_id: int,
    db: Session = Depends(get_db),
):
    """Dynamically compute the total operational cost for a vehicle.

    Sums:
    - All **fuel log** costs
    - All **expense** amounts
    - All **closed maintenance log** costs

    Returns a breakdown and the grand total.
    """
    vehicle = (
        db.query(models.Vehicle)
        .filter(models.Vehicle.id == vehicle_id)
        .first()
    )
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vehicle with id {vehicle_id} not found.",
        )

    # Sum fuel costs
    total_fuel = (
        db.query(func.coalesce(func.sum(models.FuelLog.cost), 0.0))
        .filter(models.FuelLog.vehicle_id == vehicle_id)
        .scalar()
    )

    # Sum expense amounts
    total_expense = (
        db.query(func.coalesce(func.sum(models.Expense.amount), 0.0))
        .filter(models.Expense.vehicle_id == vehicle_id)
        .scalar()
    )

    # Sum closed maintenance log costs
    total_maintenance = (
        db.query(func.coalesce(func.sum(models.MaintenanceLog.cost), 0.0))
        .filter(
            models.MaintenanceLog.vehicle_id == vehicle_id,
            models.MaintenanceLog.is_open == False,
        )
        .scalar()
    )

    return schemas.VehicleTotalCostResponse(
        vehicle_id=vehicle_id,
        total_fuel_cost=float(total_fuel),
        total_expense_cost=float(total_expense),
        total_maintenance_cost=float(total_maintenance),
        total_operational_cost=float(total_fuel + total_expense + total_maintenance),
    )


# ===========================================================================
# Dashboard & Reports (Phase 4)
# ===========================================================================

@app.get(
    "/api/dashboard/kpis",
    response_model=schemas.DashboardKPIsResponse,
    tags=["Dashboard"],
    summary="Live operational KPIs",
)
def get_dashboard_kpis(db: Session = Depends(get_db)):
    """Return live operational KPIs for the operations dashboard."""
    active_vehicles = db.query(models.Vehicle).filter(models.Vehicle.status == models.VehicleStatus.on_trip.value).count()
    available_vehicles = db.query(models.Vehicle).filter(models.Vehicle.status == models.VehicleStatus.available.value).count()
    in_maintenance_vehicles = db.query(models.Vehicle).filter(models.Vehicle.status == models.VehicleStatus.in_shop.value).count()
    
    active_trips = db.query(models.Trip).filter(models.Trip.status == models.TripStatus.dispatched.value).count()
    pending_trips = db.query(models.Trip).filter(models.Trip.status == models.TripStatus.draft.value).count()
    
    drivers_on_duty = db.query(models.Driver).filter(models.Driver.status == models.DriverStatus.on_trip.value).count()
    
    total_active = available_vehicles + active_vehicles + in_maintenance_vehicles
    fleet_utilization = (active_vehicles / total_active * 100) if total_active > 0 else 0.0

    return schemas.DashboardKPIsResponse(
        active_vehicles=active_vehicles,
        available_vehicles=available_vehicles,
        in_maintenance_vehicles=in_maintenance_vehicles,
        active_trips=active_trips,
        pending_trips=pending_trips,
        drivers_on_duty=drivers_on_duty,
        fleet_utilization=fleet_utilization,
    )


def _compute_vehicle_report(db: Session, vehicle_type: Optional[str] = None) -> List[dict]:
    """Helper to compute financial and ROI metrics for vehicles."""
    query = db.query(models.Vehicle)
    if vehicle_type:
        query = query.filter(models.Vehicle.vehicle_type == vehicle_type)
    
    vehicles = query.all()
    reports = []
    
    for v in vehicles:
        # 1. Total Distance from Completed Trips
        completed_trips = db.query(models.Trip).filter(
            models.Trip.vehicle_id == v.id,
            models.Trip.status == models.TripStatus.completed.value
        ).all()
        total_distance = sum(t.planned_distance for t in completed_trips)
        total_revenue = total_distance * 2.0  # Mock $2 per km revenue
        
        # 2. Total Fuel Cost & Liters
        fuel_logs = db.query(models.FuelLog).filter(models.FuelLog.vehicle_id == v.id).all()
        total_liters = sum(f.liters for f in fuel_logs)
        total_fuel_cost = sum(f.cost for f in fuel_logs)
        
        # 3. Total Maintenance Cost (Closed only)
        maintenance_logs = db.query(models.MaintenanceLog).filter(
            models.MaintenanceLog.vehicle_id == v.id,
            models.MaintenanceLog.is_open == False
        ).all()
        total_maintenance_cost = sum(m.cost for m in maintenance_logs)
        
        # 4. Total Expenses
        expenses = db.query(models.Expense).filter(models.Expense.vehicle_id == v.id).all()
        total_expense_cost = sum(e.amount for e in expenses)
        
        # 5. Compute Metrics
        fuel_efficiency = (total_distance / total_liters) if total_liters > 0 else 0.0
        total_op_cost = total_fuel_cost + total_maintenance_cost + total_expense_cost
        
        acquisition_cost = v.acquisition_cost or 0.0
        if acquisition_cost > 0:
            vehicle_roi = (total_revenue - (total_maintenance_cost + total_fuel_cost)) / acquisition_cost
        else:
            vehicle_roi = 0.0
            
        reports.append({
            "registration_number": v.registration_number,
            "model_name": v.model_name,
            "vehicle_type": v.vehicle_type,
            "fuel_efficiency": fuel_efficiency,
            "total_operational_cost": total_op_cost,
            "vehicle_roi": vehicle_roi,
        })
    
    return reports


@app.get(
    "/api/reports/vehicles",
    response_model=List[schemas.VehicleReportResponse],
    tags=["Reports"],
    summary="Financial report & ROI per vehicle",
)
def get_vehicle_reports(vehicle_type: Optional[str] = None, db: Session = Depends(get_db)):
    """Evaluate vehicles and output metrics including fuel efficiency and ROI."""
    return _compute_vehicle_report(db, vehicle_type)


@app.get(
    "/api/reports/export-csv",
    tags=["Reports"],
    summary="Export financial report to CSV",
)
def export_vehicles_csv(vehicle_type: Optional[str] = None, db: Session = Depends(get_db)):
    """Generate and return a streaming CSV file download containing fleet report rows."""
    reports = _compute_vehicle_report(db, vehicle_type)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Registration Number", "Fuel Efficiency", "Total Cost", "ROI"])
    
    for r in reports:
        writer.writerow([
            r["registration_number"],
            f"{r['fuel_efficiency']:.2f}",
            f"{r['total_operational_cost']:.2f}",
            f"{r['vehicle_roi']:.4f}",
        ])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vehicle_report.csv"}
    )
