package med.voll.api.domain.paciente;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface PacienteRepository extends JpaRepository<Paciente, Long> {
    Page<Paciente> findAllByActivoTrue(Pageable paginacion);

    @Query("""
            SELECT p.activo
            FROM Paciente p
            WHERE p.id = :idPaciente 
            """)
    Boolean findActivoById(Long idPaciente);
}
